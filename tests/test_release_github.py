"""Offline release-state and authenticated transport regressions."""
import copy
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import BaseHandler, build_opener
from urllib.response import addinfourl


spec = importlib.util.spec_from_file_location('github_release', Path(__file__).parents[1] / 'scripts/github_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class API:
    base = '/repos/example/cli'

    def __init__(self, revision):
        self.revision = revision
        self.tag = None
        self.releases = []
        self.assets = []
        self.writes = []
        self.fail_after = None
        self.corrupt = None
        self.annotated = False

    def pages(self, path):
        return iter(copy.deepcopy(self.assets if path.endswith('/assets') else self.releases))

    def request(self, method, path, value=None, asset=None):
        if method == 'GET':
            if '/commits/' in path:
                return {'sha': self.revision}
            if '/git/ref/' in path:
                if self.tag is None:
                    raise release.APIError(404)
                return {'object': {'type': 'tag' if self.annotated else 'commit', 'sha': self.tag}}
            if '/git/tags/' in path:
                return {'object': {'type': 'commit', 'sha': self.tag}}
            raise AssertionError(path)
        self.writes.append((method, path, value))
        if asset is not None:
            name = parse_qs(urlsplit(path).query)['name'][0]
            data = asset.read_bytes()
            item = {'name': name, 'state': 'uploaded', 'size': len(data),
                    'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
            if self.corrupt:
                item[self.corrupt[0]] = self.corrupt[1]
            self.assets.append(item)
            result = item
            operation = 'upload'
        elif method == 'POST':
            result = {**value, 'id': 1}
            self.releases.append(result)
            operation = 'create'
        elif method == 'PATCH':
            self.releases[0].update(value)
            self.tag = self.releases[0]['target_commitish']
            result = self.releases[0]
            operation = 'publish'
        else:
            raise AssertionError(method)
        if self.fail_after == operation:
            self.fail_after = None
            raise release.APIError()
        return copy.deepcopy(result)


class Releases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.staged = {name: self.directory / name for name in ('installer.deb', 'build-linux-x64.json', 'sha256sums')}
        self.expected = {}
        for name, path in self.staged.items():
            path.write_bytes(name.encode())
            self.expected[name] = {'size': path.stat().st_size, 'sha256': hashlib.sha256(name.encode()).hexdigest()}
        self.revision = 'a' * 40
        self.api = API(self.revision)

    def publish(self):
        return release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, 'Linux preview')

    def test_publish_last_and_exact_source(self):
        result = self.publish()
        self.assertFalse(result['draft'])
        self.assertEqual(self.api.tag, self.revision)
        self.assertEqual(self.api.writes[0][2]['target_commitish'], self.revision)
        self.assertTrue(self.api.writes[0][2]['draft'])
        self.assertEqual([w[0] for w in self.api.writes], ['POST'] * 4 + ['PATCH'])
        self.assertEqual(len(self.api.assets), 3)

    def test_lost_mutation_response_is_reconciled_without_duplicates(self):
        for operation in ('create', 'upload', 'publish'):
            with self.subTest(operation=operation):
                self.api = API(self.revision)
                self.api.fail_after = operation
                with self.assertRaises(release.APIError):
                    self.publish()
                if operation != 'publish':
                    self.assertTrue(self.api.releases[0]['draft'])
                self.publish()
                self.assertFalse(self.api.releases[0]['draft'])
                self.assertEqual(len(self.api.releases), 1)
                self.assertEqual(len(self.api.assets), 3)
                self.assertEqual(sum(w[0] == 'PATCH' for w in self.api.writes), 1)

    def test_matching_published_release_is_read_only(self):
        self.publish()
        self.api.writes.clear()
        self.publish()
        self.assertEqual(self.api.writes, [])

    def test_wrong_source_or_lightweight_or_annotated_tag_refuses_without_writes(self):
        for annotated in (False, True):
            self.api = API(self.revision)
            self.api.annotated = annotated
            self.api.tag = 'b' * 40
            with self.assertRaisesRegex(ValueError, 'different source'):
                self.publish()
            self.assertEqual(self.api.writes, [])
        self.api = API('b' * 40)
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            self.publish()
        self.assertEqual(self.api.writes, [])

    def test_matching_annotated_tag(self):
        self.api.tag = self.revision
        self.api.annotated = True
        self.publish()
        self.assertFalse(self.api.releases[0]['draft'])

    def test_existing_draft_requires_exact_target_when_tag_missing(self):
        self.api.releases = [{'id': 1, 'draft': True, 'tag_name': 'v0.1.0', 'target_commitish': 'main'}]
        with self.assertRaisesRegex(ValueError, 'exact draft'):
            self.publish()
        self.assertEqual(self.api.writes, [])

    def test_bad_existing_assets_refuse_before_new_writes(self):
        for published in (False, True):
            for key, value in [('digest', None), ('digest', 'sha256:' + '0' * 64),
                               ('size', 0), ('state', 'starter'), ('name', 'extra.exe')]:
                with self.subTest(published=published, key=key, value=value):
                    self.api = API(self.revision)
                    self.publish()
                    self.api.releases[0]['draft'] = not published
                    self.api.assets[0][key] = value
                    self.api.writes.clear()
                    with self.assertRaises(ValueError):
                        self.publish()
                    self.assertEqual(self.api.writes, [])

    def test_upload_verification_failure_never_publishes(self):
        for corruption in [('size', 0), ('state', 'starter'), ('digest', None), ('digest', 'sha256:' + '0' * 64)]:
            self.api = API(self.revision)
            self.api.corrupt = corruption
            with self.assertRaises(ValueError):
                self.publish()
            self.assertTrue(self.api.releases[0]['draft'])
            self.assertFalse(any(w[0] == 'PATCH' for w in self.api.writes))

    def test_incomplete_published_release_and_duplicate_assets_refuse(self):
        self.publish()
        self.api.assets.pop()
        self.api.writes.clear()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.publish()
        self.assertEqual(self.api.writes, [])
        self.api.assets.append(copy.deepcopy(self.api.assets[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.publish()


class Transport(unittest.TestCase):
    def test_fixed_origins_streaming_length_and_sanitized_errors(self):
        api = release.GitHub('example/cli', 'secret-token')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'asset.deb'
            path.write_bytes(b'abc')
            class Opener:
                def open(self, request, timeout):
                    self.request = request
                    self.data = request.data.read()
                    self.timeout = timeout
                    raise HTTPError(request.full_url, 302, 'secret-token', {'Location': 'https://evil.example'}, io.BytesIO(b'secret-token'))
            opener = Opener()
            api.opener = opener
            with self.assertRaises(release.APIError) as caught:
                api.request('POST', api.base + '/releases/1/assets?name=asset.deb', asset=path)
            self.assertNotIn('secret-token', str(caught.exception))
            self.assertEqual(urlsplit(opener.request.full_url).netloc, 'uploads.github.com')
            self.assertEqual(opener.request.get_header('Content-length'), '3')
            self.assertEqual(opener.data, b'abc')
            self.assertEqual(opener.timeout, 120)
            self.assertIsNone(release.NoRedirects().redirect_request(None, None, 302, '', {}, 'https://evil.example'))
        for repository in ('../bad', 'owner/name/path', 'https://evil.example/name', 'owner/..'):
            with self.assertRaises(ValueError):
                release.GitHub(repository, 'secret-token')

    def test_real_redirect_handler_does_not_forward_token(self):
        requests = []
        class Redirect(BaseHandler):
            handler_order = 100
            def https_open(self, request):
                requests.append(request)
                response = addinfourl(io.BytesIO(), {'Location': 'https://attacker.example/stolen'},
                                      request.full_url, 302)
                response.msg = 'Found'
                return response
        api = release.GitHub('example/cli', 'secret-token')
        api.opener = build_opener(release.NoRedirects(), Redirect())
        with self.assertRaises(release.APIError) as caught:
            api.request('GET', api.base + '/releases')
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(len(requests), 1)
        self.assertEqual(urlsplit(requests[0].full_url).hostname, 'api.github.com')

    def test_real_urllib_streams_upload_with_explicit_length(self):
        connections = []
        class Socket:
            def __init__(self):
                self.sent = []
            def sendall(self, data):
                self.sent.append(bytes(data))
            def makefile(self, mode):
                return io.BytesIO(b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}')
            def close(self):
                pass
        class Connection(http.client.HTTPConnection):
            def __init__(self, host, *, timeout, **kwargs):
                super().__init__(host, timeout=timeout)
                self.captured_socket = Socket()
                connections.append(self)
            def connect(self):
                self.sock = self.captured_socket
        api = release.GitHub('example/cli', 'secret-token')
        payload = b'installer' * 100000
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'installer.deb'
            path.write_bytes(payload)
            with patch.dict(os.environ, {}, clear=True), patch.object(http.client, 'HTTPSConnection', Connection):
                api.request('POST', api.base + '/releases/1/assets?name=installer.deb', asset=path)
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].host, 'uploads.github.com')
        headers, body = b''.join(connections[0].captured_socket.sent).split(b'\r\n\r\n', 1)
        self.assertEqual(body, payload)
        self.assertIn(f'Content-Length: {len(payload)}'.encode(), headers)
        self.assertNotIn(b'Transfer-Encoding:', headers)

    def test_pagination_finds_drafts_on_later_pages(self):
        api = release.GitHub('example/cli', 'secret-token')
        pages = [[{'id': n} for n in range(100)], [{'id': 101, 'draft': True}]]
        with patch.object(api, 'request', side_effect=pages) as request:
            values = list(api.pages(api.base + '/releases'))
        self.assertTrue(values[-1]['draft'])
        self.assertEqual(request.call_count, 2)
        self.assertTrue(request.call_args.args[1].endswith('page=2'))

class BothProviders(unittest.TestCase):
    setUp = Releases.setUp
    publish = Releases.publish
    def test_cdn_failure_keeps_draft_then_same_assets_resume_and_published_retry_checks_cdn(self):
        calls = []
        def failed():
            calls.append('cdn')
            raise ValueError('CDN readback/public/latest verification failed')
        with self.assertRaises(ValueError):
            release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=failed)
        self.assertTrue(self.api.releases[0]['draft'])
        self.assertEqual(len(self.api.assets), 3)
        self.assertFalse(any(w[0] == 'PATCH' for w in self.api.writes))
        release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=lambda: calls.append('resume'))
        writes = len(self.api.writes)
        release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=lambda: calls.append('published'))
        self.assertEqual(len(self.api.writes), writes)
        self.assertEqual(calls, ['cdn', 'resume', 'published'])
        self.assertEqual(len(self.api.assets), 3)

    def test_github_upload_failure_prevents_cdn_and_final_failure_resumes(self):
        calls = []
        self.api.fail_after = 'upload'
        with self.assertRaises(release.APIError):
            release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=lambda: calls.append('cdn'))
        self.assertEqual(calls, [])
        self.api.fail_after = 'publish'
        with self.assertRaises(release.APIError):
            release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=lambda: calls.append('cdn'))
        release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=lambda: calls.append('cdn'))
        self.assertEqual(calls, ['cdn', 'cdn'])
        self.assertEqual(len(self.api.assets), 3)

    def test_source_and_published_asset_mismatch_never_calls_cdn(self):
        self.publish()
        self.api.assets[0]['digest'] = None
        with self.assertRaises(ValueError):
            release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected,
                            before_publish=lambda: self.fail('CDN must not mutate'))

class ProviderFailures(unittest.TestCase):
    setUp = Releases.setUp
    publish = Releases.publish
    def test_actual_cdn_failure_boundaries_and_resume_use_identical_bytes(self):
        import io
        from urllib.parse import urlsplit, unquote
        cdn = __import__('cdn_release')
        class Missing(Exception):
            response = {'Error': {'Code': '404'}}
        class Storage:
            def __init__(self):
                self.objects = {}; self.fail = None; self.writes = []
            def get_object(self, *, Bucket, Key):
                if Key not in self.objects: raise Missing()
                if self.fail == 'readback' and Key.endswith('installer.deb'): return {'Body': io.BytesIO(b'bad')}
                if self.fail == 'latest-readback' and Key.endswith('latest.json'): return {'Body': io.BytesIO(b'bad')}
                return {'Body': io.BytesIO(self.objects[Key])}
            def put_object(self, *, Bucket, Key, Body, **kwargs):
                if self.fail == 'upload' and not Key.endswith('latest.json'): raise RuntimeError('storage unavailable')
                self.objects[Key] = Body.read() if hasattr(Body, 'read') else Body
                self.writes.append(Key)
        latest = {'version': '0.1.0', 'revision': self.revision, 'build': 'frozen',
                  'latest_url': 'https://cdn.example/product/latest.json',
                  'files': {name: {**item, 'url': 'https://cdn.example/product/releases/frozen/' + name}
                            for name, item in self.expected.items()}}
        for failure in ('upload', 'readback', 'public-package', 'latest-readback', 'public-latest', 'github-final'):
            with self.subTest(failure=failure):
                self.api = API(self.revision); storage = Storage()
                storage.objects['product/latest.json'] = b'previous'
                storage.fail = failure
                def public(url, expected):
                    key = unquote(urlsplit(url).path).lstrip('/')
                    if (storage.fail == 'public-package' and not key.endswith('latest.json') or
                            storage.fail == 'public-latest' and key.endswith('latest.json')):
                        raise ValueError('public checksum differs')
                    self.assertEqual(hashlib.sha256(storage.objects[key]).hexdigest(), expected)
                def callback():
                    cdn.publish(storage, 'zone', 'product', self.staged, latest,
                                'product/releases/frozen', public_check=public)
                if failure == 'github-final': self.api.fail_after = 'publish'
                with self.assertRaises((ValueError, RuntimeError, release.APIError)):
                    release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=callback)
                if failure != 'github-final':
                    self.assertTrue(self.api.releases[0]['draft'])
                if failure in ('upload', 'readback', 'public-package'):
                    self.assertEqual(storage.objects['product/latest.json'], b'previous')
                storage.fail = None
                release.publish(self.api, '0.1.0', self.revision, self.staged, self.expected, before_publish=callback)
                self.assertFalse(self.api.releases[0]['draft'])
                self.assertEqual(len(self.api.assets), len(self.staged))
                for name, path in self.staged.items():
                    self.assertEqual(storage.objects['product/releases/frozen/' + name], path.read_bytes())
                self.assertEqual(storage.writes[-1], 'product/latest.json')
