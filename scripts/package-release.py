#!/usr/bin/env python3
"""Build and validate standalone Ghost release archives (Python 3.10+)."""
import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    'x86_64-unknown-linux-musl': ('linux_x64', 'tar.gz', 'ghost'),
    'x86_64-pc-windows-msvc': ('windows_x64', 'zip', 'ghost.exe'),
    'aarch64-apple-darwin': ('macos_arm64', 'tar.gz', 'ghost'),
    'x86_64-apple-darwin': ('macos_x64', 'tar.gz', 'ghost'),
}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source():
    # Read only literal name/version fields in Cargo's package tables. Complex
    # or inherited versions fail closed rather than accepting a guessed value.
    def field(table, name):
        matches = re.findall(r'(?m)^' + name + r'\s*=\s*"([^"\\]+)"\s*$', table)
        if len(matches) != 1:
            raise ValueError('Expected one literal Cargo ' + name)
        return matches[0]
    tables = re.findall(r'(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)', (ROOT / 'Cargo.toml').read_text())
    if len(tables) != 1:
        raise ValueError('Expected one Cargo package table')
    version = field(tables[0], 'version')
    packages = re.split(r'(?m)^\[\[package\]\]\s*$', (ROOT / 'Cargo.lock').read_text())[1:]
    if [field(p, 'version') for p in packages if field(p, 'name') == 'ghost'] != [version]:
        raise ValueError('Cargo package and lock versions differ')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', version):
        raise ValueError('Invalid Cargo package version')
    key_lines = [line.split() for line in (ROOT / 'config/console-host-key.pub').read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
    if len(key_lines) != 1 or len(key_lines[0]) < 2 or key_lines[0][0] != 'ssh-ed25519':
        raise ValueError('Invalid public console host key')
    try:
        key = base64.b64decode(key_lines[0][1], validate=True)
    except ValueError:
        raise ValueError('Invalid public console host key') from None
    if len(key) != 51 or key[:19] != bytes.fromhex('0000000b7373682d6564323535313900000020'):
        raise ValueError('Invalid public console host key')
    actual_root = subprocess.check_output(['git', '--no-replace-objects', 'rev-parse', '--show-toplevel'], cwd=ROOT, text=True).strip()
    if Path(actual_root).resolve() != ROOT or not (ROOT / '.git').exists() or (ROOT / '.git').is_symlink():
        raise ValueError('Release source must own its Git checkout')
    revision = subprocess.check_output(['git', '--no-replace-objects', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(['git', '--no-replace-objects', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT, text=True).strip()
    if dirty or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Release requires a clean source checkout')
    ref = os.environ.get('GITHUB_REF', '')
    if ref.startswith('refs/tags/') and ref != 'refs/tags/v' + version:
        raise ValueError('Tag must match Cargo package version')
    return version, revision


def release_id(revision):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Invalid release source revision')
    timestamp = subprocess.check_output(['git', '--no-replace-objects', 'show', '-s', '--format=%ct', revision], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[0-9]{1,12}', timestamp):
        raise ValueError('Invalid source commit timestamp')
    return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + revision[:12]


def architecture(data, target):
    if target not in TARGETS or not data:
        raise ValueError('Unknown target or empty binary')
    try:
        if target.endswith('linux-musl'):
            if (data[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 62 or
                    struct.unpack_from('<H', data, 16)[0] not in (2, 3)):
                raise ValueError('Expected x86_64 ELF executable')
            offset = struct.unpack_from('<Q', data, 32)[0]
            size, count = struct.unpack_from('<HH', data, 54)
            if size < 56 or not count or offset + size * count > len(data):
                raise ValueError('Invalid ELF program headers')
            for i in range(count):
                header = offset + size * i
                kind = struct.unpack_from('<I', data, header)[0]
                if kind == 3:
                    raise ValueError('Linux binary must be static musl without interpreter')
                if kind == 2:
                    # Static PIE uses PT_DYNAMIC for its own relocations. It is
                    # static when no DT_NEEDED shared-library entry exists.
                    start = struct.unpack_from('<Q', data, header + 8)[0]
                    length = struct.unpack_from('<Q', data, header + 32)[0]
                    if not length or length % 16 or start + length > len(data):
                        raise ValueError('Invalid static musl dynamic table')
                    terminated = False
                    for pos in range(start, start + length, 16):
                        entry = struct.unpack_from('<q', data, pos)[0]
                        if entry == 1:
                            raise ValueError('Linux binary must be static musl without shared dependencies')
                        if entry == 0:
                            terminated = True
                            break
                    if not terminated:
                        raise ValueError('Invalid static musl dynamic table')
        elif target.endswith('windows-msvc'):
            if data[:2] != b'MZ':
                raise ValueError('Expected PE executable')
            offset = struct.unpack_from('<I', data, 60)[0]
            if (data[offset:offset+4] != b'PE\0\0' or struct.unpack_from('<H', data, offset+4)[0] != 0x8664 or
                    struct.unpack_from('<H', data, offset+24)[0] != 0x20b or
                    not struct.unpack_from('<H', data, offset+22)[0] & 2):
                raise ValueError('Expected x86_64 PE executable')
        else:
            cpu = 0x100000c if target.startswith('aarch64') else 0x1000007
            if (len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xfeedfacf or
                    struct.unpack_from('<I', data, 4)[0] != cpu or struct.unpack_from('<I', data, 12)[0] != 2):
                raise ValueError('Expected native 64-bit Mach-O executable')
    except struct.error:
        raise ValueError('Truncated executable header') from None


def archive_name(version, target):
    platform, extension, _ = TARGETS[target]
    return f'ghost_{version}_{platform}.{extension}'


def validate(directory, target, version, revision):
    _, extension, executable = TARGETS[target]
    name = archive_name(version, target)
    required = {name, 'build.json', 'sha256sums'}
    if target.endswith('linux-musl'):
        required.add(release_id(revision) + '.tar.gz')
    if set(p.name for p in directory.iterdir()) != required or any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError('Artifact directory must contain exactly archive, build.json and sha256sums')
    path = directory / name
    record_bytes = (directory / 'build.json').read_bytes()
    record = json.loads(record_bytes)
    if (set(record) != {'cli', 'target', 'version', 'release_id', 'sha256'} or record['cli'] != {'commit': revision, 'dirty': False}
            or record['release_id'] != release_id(revision) or record['target'] != target or record['version'] != version or set(record['sha256']) != {executable}):
        raise ValueError('Build record source, version or target differs')
    checksums = ''.join(f'{sha((directory / n).read_bytes())}  ./{n}\n' for n in sorted(required - {'build.json', 'sha256sums'})).encode()
    if (directory / 'sha256sums').read_bytes() != checksums:
        raise ValueError('Archive checksum differs')
    members = {}
    allowed = {'bin/' + executable, 'lib/gigahost/cli-release', 'LICENSE', 'build.json'}
    if extension == 'zip':
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                mode = info.external_attr >> 16
                if (info.filename not in allowed or info.filename in members or info.is_dir() or
                        stat.S_IFMT(mode) != stat.S_IFREG or
                        stat.S_IMODE(mode) != (0o755 if info.filename == 'bin/' + executable else 0o644)):
                    raise ValueError('Invalid ZIP member')
                members[info.filename] = archive.read(info)
    else:
        with tarfile.open(path, 'r:gz') as archive:
            for info in archive:
                if (info.name not in allowed or info.name in members or not info.isfile() or
                        info.mode != (0o755 if info.name == 'bin/' + executable else 0o644)):
                    raise ValueError('Invalid tar member')
                members[info.name] = archive.extractfile(info).read()
    if set(members) != allowed:
        raise ValueError('Archive member allowlist differs')
    if members['build.json'] != record_bytes or members['LICENSE'] != (ROOT / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Embedded build record or license differs')
    if members['lib/gigahost/cli-release'] != (record['release_id'] + '\n').encode():
        raise ValueError('Embedded release identity differs')
    if record['sha256'][executable] != sha(members['bin/' + executable]):
        raise ValueError('Executable hash differs')
    architecture(members['bin/' + executable], target)
    if target.endswith('linux-musl'):
        validate_install(directory / (record['release_id'] + '.tar.gz'), record['release_id'], members['bin/' + executable])
    return path, record_bytes


def write_tar(path, members, executable):
    # filename='' avoids embedding the output path in the gzip header.
    with path.open('wb') as out, gzip.GzipFile(filename='', fileobj=out, mode='wb', mtime=0) as zipped, tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, value in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            info.mode = 0o755 if name == executable else 0o644
            archive.addfile(info, io.BytesIO(value))


def validate_install(path, identity, binary):
    members = {}
    with tarfile.open(path, 'r:gz') as archive:
        for info in archive:
            if (info.name not in {'VERSION', 'ghost'} or info.name in members or
                    not info.isfile() or info.mode != (0o755 if info.name == 'ghost' else 0o644) or
                    info.uid != 0 or info.gid != 0 or info.uname or info.gname or info.mtime != 0):
                raise ValueError('Invalid installer archive member')
            members[info.name] = archive.extractfile(info).read()
    if members != {'VERSION': (identity + '\n').encode(), 'ghost': binary}:
        raise ValueError('Installer archive identity or binary differs')
    architecture(members['ghost'], 'x86_64-unknown-linux-musl')


def package(binary, target, directory, version, revision):
    data = binary.read_bytes()
    if binary.is_symlink():
        raise ValueError('Binary must not be a symlink')
    architecture(data, target)
    executable = TARGETS[target][2]
    record = json_bytes({'cli': {'commit': revision, 'dirty': False}, 'target': target,
                         'version': version, 'release_id': release_id(revision), 'sha256': {executable: sha(data)}})
    directory.mkdir(parents=True, exist_ok=False)
    members = {'bin/' + executable: data, 'lib/gigahost/cli-release': (release_id(revision) + '\n').encode(), 'LICENSE': (ROOT / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'), 'build.json': record}
    path = directory / archive_name(version, target)
    if path.suffix == '.zip':
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in members.items():
                info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                info.external_attr = (stat.S_IFREG | (0o755 if name == 'bin/' + executable else 0o644)) << 16
                archive.writestr(info, value)
    else:
        write_tar(path, members, 'bin/' + executable)
    if target.endswith('linux-musl'):
        write_tar(directory / (release_id(revision) + '.tar.gz'),
                  {'VERSION': (release_id(revision) + '\n').encode(), 'ghost': data}, 'ghost')
    (directory / 'build.json').write_bytes(record)
    archives = sorted(p for p in directory.iterdir() if p.name != 'build.json')
    (directory / 'sha256sums').write_bytes(''.join(f'{sha(p.read_bytes())}  ./{p.name}\n' for p in archives).encode())
    validate(directory, target, version, revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=TARGETS)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    version, revision = source()
    package(args.binary, args.target, args.output, version, revision)
    path, _ = validate(args.output, args.target, version, revision)
    # Execute the packaged bytes from their actual installation layout so the
    # unchanged CLI discovers its release marker exactly as users will.
    with tempfile.TemporaryDirectory(prefix='ghost-native-') as temporary:
        prefix = Path(temporary)
        if path.suffix == '.zip':
            with zipfile.ZipFile(path) as archive:
                archive.extractall(prefix)
        else:
            with tarfile.open(path) as archive:
                archive.extractall(prefix)
        executable = prefix / 'bin' / TARGETS[args.target][2]
        executable.chmod(0o755)
        for command in ('--version', '--help'):
            output = subprocess.check_output([str(executable), command], text=True, timeout=30)
            if not output.strip() or (command == '--version' and output.strip() != 'ghost ' + release_id(revision)):
                raise ValueError('Native executable version/help check failed')


if __name__ == '__main__':
    main()
