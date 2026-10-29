"""Real ephemeral Ed25519 signing and canonical installer compatibility."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import release_signing as signing


class Signing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'key.pem'; self.public = self.root / 'public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(self.key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.public)], check=True, capture_output=True)
        self.release = {'version': '20261029T000000Z-aaaaaaaaaaaa',
                        'archive_url': 'https://cdn.example/cli-github/releases/20261029T000000Z-aaaaaaaaaaaa.tar.gz',
                        'sha256': 'a' * 64}

    def test_canonical_newline_deterministic_signature_and_real_verification(self):
        expected = ('{"archive_url":"' + self.release['archive_url'] + '","sha256":"' + 'a' * 64 + '","version":"' + self.release['version'] + '"}\n').encode()
        self.assertEqual(signing.canonical(self.release), expected)
        first = signing.sign(self.release, self.key.read_text(), self.public)
        self.assertEqual(first, signing.sign(self.release, self.key.read_text(), self.public))
        manifest = json.loads(first)
        self.assertEqual(len(base64.b64decode(manifest['signature'])), 64)
        signing.verify(manifest, self.public)
        for value in ('!', base64.b64encode(b'x' * 63).decode(), base64.b64encode(b'x' * 64).decode()):
            with self.assertRaises(ValueError): signing.verify({**manifest, 'signature': value}, self.public)
        mutated = copy.deepcopy(manifest); mutated['release']['sha256'] = 'b' * 64
        with self.assertRaises(ValueError): signing.verify(mutated, self.public)
        with self.assertRaises(ValueError): signing.verify({**manifest, 'extra': 1}, self.public)

    def test_missing_wrong_malformed_signer_and_public_algorithm_fail_closed(self):
        for private in ('', 'NOT A KEY', None):
            with self.assertRaises(ValueError) as error: signing.sign(self.release, private, self.public)
            self.assertNotIn('NOT A KEY', str(error.exception))
        other = self.root / 'other.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(other)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'does not match'):
            signing.sign(self.release, other.read_text(), self.public)
        self.public.write_text('not a public key')
        with self.assertRaises(ValueError): signing.sign(self.release, self.key.read_text(), self.public)

    def test_openssl_children_have_no_secrets_and_temporary_key_is_private_and_removed(self):
        original = subprocess.run; key_paths = []
        def run(command, **kwargs):
            self.assertEqual(kwargs['env'], {'PATH': os.defpath, 'LANG': 'C'})
            self.assertTrue(kwargs['capture_output']); self.assertEqual(kwargs['timeout'], 15)
            if '-pubin' not in command and ('-inkey' in command or ('-in' in command and 'pkey' in command)):
                p = Path(command[command.index('-inkey' if '-inkey' in command else '-in') + 1])
                self.assertEqual(p.stat().st_mode & 0o777, 0o600); key_paths.append(p)
            return original(command, **kwargs)
        with patch.dict(os.environ, {'CLI_RELEASE_SIGNING_KEY': 'do-not-inherit', 'GITHUB_TOKEN': 'do-not-inherit', 'OPENSSL_CONF': '/invalid'}), patch.object(signing.subprocess, 'run', side_effect=run):
            signing.sign(self.release, self.key.read_text(), self.public)
        self.assertTrue(key_paths)
        self.assertTrue(all(not p.exists() for p in key_paths))
