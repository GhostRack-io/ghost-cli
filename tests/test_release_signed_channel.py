"""Both-provider frozen signed assets, ordered commit points and recovery."""
import hashlib
import json
from urllib.parse import unquote, urlsplit
import unittest
from unittest.mock import patch

import test_release_package as fixtures
from test_release_package import publisher
from test_release_cdn import Storage
from test_release_github import API, release as github


class SignedChannel(unittest.TestCase):
    setUp = fixtures.Packages.setUp
    prepare = fixtures.Packages.prepare

    def publish(self, storage, staged, latest, prefix, public=None):
        def check(url, digest):
            key = unquote(urlsplit(url).path).lstrip('/')
            self.assertEqual(hashlib.sha256(storage.objects[key]).hexdigest(), digest)
            if public: public(key)
        publisher.cdn.publish(storage, 'zone', 'cli-github', staged, latest, prefix,
                              public_check=check, signed_manifest=self.release_id + '.manifest.json')

    def test_exact_eleven_assets_flat_aliases_and_last_signed_pointer_preserve_others(self):
        staged, latest, prefix = self.prepare()
        storage = Storage()
        untouched = {'cli/releases/manifest.json': b'old signed manifest',
                     'cli/releases/old.tar.gz': b'old installer', 'desktop/latest.json': b'unrelated'}
        storage.objects.update(untouched)
        self.publish(storage, staged, latest, prefix)
        self.assertEqual(len(staged), 11)
        aggregate = staged['sha256sums'].read_text().splitlines()
        self.assertEqual(len(aggregate), 10)
        for line in aggregate:
            checksum, name = line.split('  ./')
            self.assertEqual(checksum, hashlib.sha256(staged[name].read_bytes()).hexdigest())
        manifest_name = self.release_id + '.manifest.json'
        manifest = json.loads(staged[manifest_name].read_bytes())
        publisher.signing.verify(manifest, self.public)
        self.assertEqual(manifest['release']['archive_url'], 'https://cdn.example/cli-github/releases/' + self.release_id + '.tar.gz')
        self.assertEqual(manifest['release']['sha256'], latest['files'][self.release_id + '.tar.gz']['sha256'])
        for name, path in staged.items():
            self.assertEqual(storage.objects[prefix + '/' + name], path.read_bytes())
        for name in (self.release_id + '.tar.gz', manifest_name):
            self.assertEqual(storage.objects['cli-github/releases/' + name], staged[name].read_bytes())
        self.assertEqual(storage.objects['cli-github/releases/manifest.json'], staged[manifest_name].read_bytes())
        self.assertEqual(storage.writes[-2:], ['cli-github/latest.json', 'cli-github/releases/manifest.json'])
        self.assertEqual({k: storage.objects[k] for k in untouched}, untouched)
        self.assertTrue(all(k.startswith('cli-github/') for k in storage.writes))
        api = API(self.revision)
        github.publish(api, self.version, self.revision, staged, latest['files'], tag_prefix='v',
                       before_publish=lambda: self.publish(storage, staged, latest, prefix))
        self.assertEqual({a['name'] for a in api.assets}, set(staged))
        self.assertFalse(api.releases[0]['draft'])

    def test_all_immutable_locations_preflight_before_first_write(self):
        staged, latest, prefix = self.prepare()
        for conflict in [prefix + '/' + n for n in staged] + ['cli-github/releases/' + self.release_id + suffix for suffix in ('.tar.gz', '.manifest.json')]:
            storage = Storage(); storage.objects[conflict] = b'conflicting'
            with self.assertRaisesRegex(ValueError, 'Immutable'): self.publish(storage, staged, latest, prefix)
            self.assertEqual(storage.writes, [])

    def test_signer_failure_precedes_any_provider_call(self):
        out = self.root / 'bad-signer'; out.mkdir()
        with patch.object(publisher, 'GitHub', side_effect=AssertionError('must not call')):
            with self.assertRaises(ValueError):
                publisher.prepare(self.inputs, out, self.version, self.revision, 'cli-github',
                                  'https://cdn.example', 'not a signing key', self.public)

    def test_failure_boundaries_and_matching_published_retry(self):
        staged, latest, prefix = self.prepare()
        first_asset = next(iter(staged))
        for failure in ('upload', 'readback', 'public-immutable', 'catalog-upload', 'catalog-readback',
                        'catalog-public', 'signed-upload', 'signed-readback', 'signed-public', 'github-final'):
            with self.subTest(failure=failure):
                storage = Storage(); api = API(self.revision)
                storage.objects.update({'cli-github/latest.json': b'previous catalog',
                                        'cli-github/releases/manifest.json': b'previous manifest'})
                manifest_key = 'cli-github/releases/manifest.json'; catalog_key = 'cli-github/latest.json'
                storage.fail_key = {'upload': prefix + '/' + first_asset,
                                    'catalog-upload': catalog_key, 'signed-upload': manifest_key}.get(failure)
                storage.corrupt_key = {'readback': prefix + '/' + first_asset,
                                       'catalog-readback': catalog_key, 'signed-readback': manifest_key}.get(failure)
                def public(key):
                    if ((failure == 'public-immutable' and key not in (catalog_key, manifest_key)) or
                            (failure == 'catalog-public' and key == catalog_key) or
                            (failure == 'signed-public' and key == manifest_key)):
                        raise ValueError('public verification failure')
                def callback(): self.publish(storage, staged, latest, prefix, public)
                if failure == 'github-final': api.fail_after = 'publish'
                with self.assertRaises((ValueError, RuntimeError, github.APIError)):
                    github.publish(api, self.version, self.revision, staged, latest['files'], tag_prefix='v', before_publish=callback)
                if failure != 'github-final': self.assertTrue(api.releases[0]['draft'])
                if failure in ('upload', 'readback', 'public-immutable', 'catalog-upload', 'catalog-readback', 'catalog-public'):
                    self.assertEqual(storage.objects[manifest_key], b'previous manifest')
                # A deliberately corrupted immutable object cannot be repaired by
                # clobbering. Remove only the simulated corruption in the fixture.
                if failure == 'readback':
                    storage.objects[prefix + '/' + first_asset] = staged[first_asset].read_bytes()
                storage.fail_key = None; storage.corrupt_key = None
                callback = lambda: self.publish(storage, staged, latest, prefix)
                github.publish(api, self.version, self.revision, staged, latest['files'], tag_prefix='v', before_publish=callback)
                self.assertFalse(api.releases[0]['draft'])
                self.assertEqual(len(api.assets), 11)
                writes = len(api.writes)
                github.publish(api, self.version, self.revision, staged, latest['files'], tag_prefix='v', before_publish=callback)
                self.assertEqual(len(api.writes), writes)
                self.assertEqual(storage.writes[-1], manifest_key)
