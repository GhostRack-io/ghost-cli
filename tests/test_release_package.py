"""Exercise real tar/ZIP artifacts, binary guards and frozen publication inputs."""
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import os
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).parents[1] / 'scripts/publish-release.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
pkg = publisher.package


def binary(target):
    data = bytearray(512)
    if 'linux' in target:
        data[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', data, 16, 2, 62, 1)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<I', data, 64, 1)
    elif 'windows' in target:
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, 0x8664)
        struct.pack_into('<H', data, 86, 2)
        struct.pack_into('<H', data, 88, 0x20b)
    else:
        struct.pack_into('<IIII', data, 0, 0xfeedfacf, 0x100000c if target.startswith('aarch64') else 0x1000007, 0, 2)
    return bytes(data)


class Packages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.inputs = self.root / 'packages'; self.inputs.mkdir()
        self.version = '0.1.0'; self.revision = 'a' * 40
        self.key = self.root / 'key.pem'; self.public = self.root / 'public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(self.key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.public)], check=True, capture_output=True)
        self.release_id = '20261029T000000Z-aaaaaaaaaaaa'
        mock_id = patch.object(pkg, 'release_id', return_value=self.release_id)
        mock_id.start(); self.addCleanup(mock_id.stop)
        for target in pkg.TARGETS:
            path = self.root / target; path.write_bytes(binary(target))
            pkg.package(path, target, self.inputs / target, self.version, self.revision)

    def prepare(self):
        out = self.root / 'staged'
        if out.exists(): shutil.rmtree(out)
        out.mkdir()
        return publisher.prepare(self.inputs, out, self.version, self.revision, 'cli-github', 'https://cdn.example', self.key.read_text(), self.public)

    def rechecksum(self, directory):
        paths = sorted(p for p in directory.iterdir() if p.name not in {'build.json', 'sha256sums'})
        (directory / 'sha256sums').write_bytes(''.join(f'{pkg.sha(p.read_bytes())}  ./{p.name}\n' for p in paths).encode())

    def test_install_archive_determinism_and_tampering(self):
        target = 'x86_64-unknown-linux-musl'
        directory = self.inputs / target
        path = directory / (self.release_id + '.tar.gz')
        original = path.read_bytes()
        second = self.root / 'second'
        pkg.package(self.root / target, target, second, self.version, self.revision)
        self.assertEqual(original, (second / path.name).read_bytes())
        with tarfile.open(path) as archive:
            self.assertEqual(archive.getnames(), ['VERSION', 'ghost'])
        cases = [('VERSION', b'wrong', 0o644, tarfile.REGTYPE),
                 ('ghost', b'bad', 0o755, tarfile.REGTYPE),
                 ('../ghost', binary(target), 0o755, tarfile.REGTYPE),
                 ('ghost', binary(target), 0o644, tarfile.REGTYPE),
                 ('ghost', b'', 0o755, tarfile.SYMTYPE),
                 ('extra', b'extra', 0o644, tarfile.REGTYPE)]
        for name, data, mode, kind in cases:
            with self.subTest(name=name, mode=mode, kind=kind):
                with tarfile.open(path, 'w:gz') as archive:
                    for n, value in {'VERSION': (self.release_id + '\n').encode(), 'ghost': binary(target)}.items():
                        if n == name: continue
                        info = tarfile.TarInfo(n); info.size = len(value); info.mode = 0o755 if n == 'ghost' else 0o644
                        archive.addfile(info, io.BytesIO(value))
                    info = tarfile.TarInfo(name); info.size = len(data); info.mode = mode; info.type = kind; info.linkname = '../escape' if kind == tarfile.SYMTYPE else ''
                    archive.addfile(info, io.BytesIO(data))
                self.rechecksum(directory)
                with self.assertRaises(ValueError): self.prepare()
        path.write_bytes(original); self.rechecksum(directory)
        self.prepare()

    def test_unsigned_dry_preparation_and_fixed_channel(self):
        out = self.root / 'unsigned'; out.mkdir()
        staged, _, _ = publisher.prepare(self.inputs, out, self.version, self.revision, 'cli-github', 'https://cdn.example')
        self.assertEqual(len(staged), 10)
        self.assertFalse(any(n.endswith('.manifest.json') for n in staged))
        with self.assertRaises(ValueError):
            publisher.prepare(self.inputs, out, self.version, self.revision, 'cli', 'https://cdn.example')
        for url in ('http://cdn.example', 'https://cdn.example/a b', 'https://cdn.example\n/evil',
                    'https://user:password@cdn.example', 'https://cdn.example?query=1', 'https://cdn.example:0'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                publisher.prepare(self.inputs, out, self.version, self.revision, 'cli-github', url)

    def test_all_four_native_archives_and_eleven_frozen_assets(self):
        staged, latest, prefix = self.prepare()
        self.assertEqual(len(staged), 11)
        self.assertEqual(len(latest['downloads']), 4)
        self.assertTrue(prefix.startswith('cli-github/releases/0.1.0-' + self.revision[:12]))
        for target in pkg.TARGETS:
            archive, record = pkg.validate(self.inputs / target, target, self.version, self.revision)
            self.assertEqual(archive.name, pkg.archive_name(self.version, target))
            self.assertEqual(json.loads(record)['cli'], {'commit': self.revision, 'dirty': False})
        for name, path in staged.items():
            self.assertEqual(pkg.sha(path.read_bytes()), latest['files'][name]['sha256'])
        archive = next(p for n, p in staged.items() if n.endswith('.zip'))
        original = archive.read_bytes()
        (self.inputs / 'x86_64-pc-windows-msvc' / archive.name).write_bytes(b'replaced')
        self.assertEqual(archive.read_bytes(), original)

    def test_missing_extra_target_and_bad_metadata_hash_source_version(self):
        for key, value in [('cli', {'commit': self.revision, 'dirty': True}), ('version', '9.0.0'),
                           ('target', 'wrong'), ('sha256', {'ghost': '0' * 64})]:
            path = self.inputs / 'x86_64-unknown-linux-musl' / 'build.json'
            original = path.read_bytes(); record = json.loads(original); record[key] = value
            path.write_bytes(pkg.json_bytes(record))
            with self.assertRaises(ValueError): self.prepare()
            path.write_bytes(original)
        target = next(iter(pkg.TARGETS)); source = self.inputs / target
        source.rename(self.inputs / 'wrong-target')
        with self.assertRaises(ValueError): self.prepare()
        (self.inputs / 'wrong-target').rename(source)
        (source / 'extra').write_text('extra')
        with self.assertRaises(ValueError): self.prepare()

    def test_archive_checksum_architecture_and_static_linkage_guards(self):
        for target in pkg.TARGETS:
            with self.assertRaises(ValueError): pkg.architecture(b'bad', target)
            for other in pkg.TARGETS:
                if other != target:
                    with self.assertRaises(ValueError): pkg.architecture(binary(other), target)
        data = bytearray(binary('x86_64-unknown-linux-musl'))
        for kind in (2, 3):
            struct.pack_into('<I', data, 64, kind)
            with self.assertRaisesRegex(ValueError, 'static musl'): pkg.architecture(data, 'x86_64-unknown-linux-musl')
        directory = self.inputs / 'x86_64-pc-windows-msvc'
        archive = next(directory.glob('*.zip')); archive.write_bytes(archive.read_bytes() + b'bad')
        with self.assertRaisesRegex(ValueError, 'checksum'): self.prepare()

    def test_tar_and_zip_members_paths_symlinks_license_embedded_record(self):
        for target in ('x86_64-unknown-linux-musl', 'x86_64-pc-windows-msvc'):
            directory = self.inputs / target; path = directory / pkg.archive_name(self.version, target)
            original = path.read_bytes()
            for name in ('../escape', '/absolute', 'extra', 'LICENSE', 'build.json'):
                if path.suffix == '.zip':
                    with zipfile.ZipFile(path, 'w') as archive:
                        archive.writestr(name, b'bad')
                else:
                    with tarfile.open(path, 'w:gz') as archive:
                        info = tarfile.TarInfo(name); info.size = 3; archive.addfile(info, io.BytesIO(b'bad'))
                self.rechecksum(directory)
                with self.assertRaises(ValueError): self.prepare()
            if path.suffix != '.zip':
                with tarfile.open(path, 'w:gz') as archive:
                    info = tarfile.TarInfo('ghost'); info.type = tarfile.SYMTYPE; info.linkname = '../escape'; archive.addfile(info)
            else:
                with zipfile.ZipFile(path, 'w') as archive:
                    info = zipfile.ZipInfo('ghost.exe'); info.external_attr = 0o120777 << 16; archive.writestr(info, '../escape')
            self.rechecksum(directory)
            with self.assertRaises(ValueError): self.prepare()
            path.write_bytes(original)
            self.rechecksum(directory)

    def test_host_pin_lock_dirty_and_tag_checks(self):
        with patch.object(pkg.subprocess, 'check_output', side_effect=[str(pkg.ROOT), self.revision + '\n', ' M README.md\n']):
            with self.assertRaisesRegex(ValueError, 'clean source'): pkg.source()
        with patch.object(pkg.subprocess, 'check_output', side_effect=[str(pkg.ROOT), self.revision + '\n', '']), patch.dict(pkg.os.environ, {'GITHUB_REF': 'refs/tags/v9.9.9'}):
            with self.assertRaisesRegex(ValueError, 'Tag must match'): pkg.source()
        # A portable check rejects malformed pins before consulting Git.
        with patch.object(Path, 'read_text', return_value=''):
            with self.assertRaises((ValueError, KeyError)): pkg.source()

    def test_native_version_and_help_are_checked_from_packaged_layout(self):
        target = 'x86_64-unknown-linux-musl'
        output = self.root / 'native-result'
        argv = ['package-release.py', '--target', target, '--binary', str(self.root / target), '--output', str(output)]
        with patch.object(pkg, 'source', return_value=(self.version, self.revision)), patch.object(pkg.os.sys, 'argv', argv), patch.object(pkg.subprocess, 'check_output', side_effect=['ghost ' + self.release_id + '\n', 'Usage: ghost <COMMAND>\n']):
            pkg.main()
        pkg.validate(output, target, self.version, self.revision)
        shutil.rmtree(output)
        with patch.object(pkg, 'source', return_value=(self.version, self.revision)), patch.object(pkg.os.sys, 'argv', argv), patch.object(pkg.subprocess, 'check_output', return_value='ghost 9.9.9\n'):
            with self.assertRaisesRegex(ValueError, 'version/help'): pkg.main()
        self.assertTrue(output.exists())

    def test_static_pie_relocations_are_allowed_but_needed_libraries_are_not(self):
        target = 'x86_64-unknown-linux-musl'
        data = bytearray(binary(target))
        struct.pack_into('<I', data, 64, 2)
        struct.pack_into('<Q', data, 72, 256)
        struct.pack_into('<Q', data, 96, 32)
        struct.pack_into('<qQ', data, 256, 7, 128)
        struct.pack_into('<qQ', data, 272, 0, 0)
        pkg.architecture(data, target)
        struct.pack_into('<qQ', data, 256, 1, 128)
        with self.assertRaisesRegex(ValueError, 'shared dependencies'):
            pkg.architecture(data, target)

    def test_complete_archive_member_tampering_is_detected_after_rechecksum(self):
        for target in ('x86_64-unknown-linux-musl', 'x86_64-pc-windows-msvc'):
            directory = self.inputs / target
            path = directory / pkg.archive_name(self.version, target)
            original = path.read_bytes()
            if path.suffix == '.zip':
                with zipfile.ZipFile(path) as archive: members = {n: archive.read(n) for n in archive.namelist()}
            else:
                with tarfile.open(path) as archive: members = {m.name: archive.extractfile(m).read() for m in archive}
            for name in ('LICENSE', 'build.json', 'lib/gigahost/cli-release', 'bin/' + pkg.TARGETS[target][2]):
                mutated = {**members, name: b'tampered'}
                if path.suffix == '.zip':
                    with zipfile.ZipFile(path, 'w') as archive:
                        for n, data in mutated.items():
                            info = zipfile.ZipInfo(n); info.external_attr = (0o100755 if n.startswith('bin/') else 0o100644) << 16; archive.writestr(info, data)
                else:
                    with tarfile.open(path, 'w:gz') as archive:
                        for n, data in mutated.items():
                            info = tarfile.TarInfo(n); info.size = len(data); info.mode = 0o755 if n.startswith('bin/') else 0o644; archive.addfile(info, io.BytesIO(data))
                self.rechecksum(directory)
                with self.assertRaises(ValueError): self.prepare()
            path.write_bytes(original)
            self.rechecksum(directory)

    def test_real_lock_version_pin_and_source_metadata_preconditions(self):
        original = Path.read_text
        for mutation, message in [('version', 'package and lock'), ('pin', 'console host key')]:
            def read(path, *args, **kwargs):
                text = original(path, *args, **kwargs)
                if mutation == 'version' and path.name == 'Cargo.toml':
                    return text.replace('version = "0.1.0"', 'version = "0.2.0"', 1)
                if mutation == 'pin' and path.name == 'console-host-key.pub':
                    return 'ssh-ed25519 PLACEHOLDER\n'
                return text
            with patch.object(Path, 'read_text', read):
                with self.assertRaisesRegex(ValueError, message): pkg.source()


class SourceReleaseIdentity(unittest.TestCase):
    def test_source_timestamp_and_sha_derive_existing_cli_release_format(self):
        with patch.object(pkg.subprocess, 'check_output', return_value='1793232000\n') as command:
            self.assertEqual(pkg.release_id('a' * 40), '20261029T000000Z-aaaaaaaaaaaa')
            self.assertEqual(command.call_args.args[0][-1], 'a' * 40)
        for revision in ('main', 'a' * 12, 'z' * 40):
            with self.assertRaises(ValueError): pkg.release_id(revision)
        with patch.object(pkg.subprocess, 'check_output', return_value='not-a-timestamp'):
            with self.assertRaises(ValueError): pkg.release_id('a' * 40)


class RealGitSource(unittest.TestCase):
    def test_original_commit_epoch_replacement_objects_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args, **kwargs):
                return subprocess.check_output(['git', *args], cwd=root, text=True, **kwargs).strip()
            git('init', '-q')
            git('config', 'user.email', 'release-test@example.invalid')
            git('config', 'user.name', 'Release Test')
            for name in ('Cargo.toml', 'Cargo.lock', 'config/console-host-key.pub'):
                dest = root / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes((pkg.ROOT / name).read_bytes())
            (root / 'tracked').write_text('original')
            git('add', '.')
            epoch = '1793232000'
            env = dict(os.environ, GIT_AUTHOR_DATE='@' + epoch + ' +0000', GIT_COMMITTER_DATE='@' + epoch + ' +0000')
            git('commit', '-qm', 'fixture', env=env)
            original = git('rev-parse', 'HEAD')
            (root / 'tracked').write_text('replacement')
            git('add', 'tracked')
            git('commit', '-qm', 'replacement')
            replacement = git('rev-parse', 'HEAD')
            git('checkout', '--detach', original)
            git('replace', original, replacement)
            with patch.object(pkg, 'ROOT', root), patch.dict(os.environ, {'GITHUB_REF': '', 'SOURCE_DATE_EPOCH': '1'}):
                self.assertEqual(pkg.source(), ('0.1.0', original))
                self.assertEqual(pkg.release_id(original), '20261029T000000Z-' + original[:12])
                (root / 'tracked').write_text('replacement')
                with self.assertRaisesRegex(ValueError, 'clean source'): pkg.source()
                (root / 'tracked').write_text('original')
                (root / 'extra').mkdir(); (root / 'extra/untracked').write_text('new')
                with self.assertRaisesRegex(ValueError, 'clean source'): pkg.source()
