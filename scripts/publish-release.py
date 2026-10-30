#!/usr/bin/env python3
"""Validate four native artifacts and publish identical GitHub/CDN release bytes."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).parent))
import cdn_release as cdn
import release_signing as signing

PREFIX = 'cli-github'
from github_release import GitHub, publish
spec = importlib.util.spec_from_file_location('package_release', Path(__file__).with_name('package-release.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def prepare(packages, directory, version, revision, prefix, public_base, private_pem=None, public_key=signing.PUBLIC_KEY):
    if prefix != PREFIX:
        raise ValueError('Invalid CDN prefix')
    public_base = cdn.validate_url(public_base, 'Public base URL')
    if set(p.name for p in packages.iterdir()) != set(package.TARGETS):
        raise ValueError('Exactly four native target artifacts are required')
    staged = {}; downloads = {}
    for target, (platform, _, _) in package.TARGETS.items():
        source_dir = packages / target
        if source_dir.is_symlink() or not source_dir.is_dir():
            raise ValueError('Artifact target must be a real directory')
        frozen = directory / target
        frozen.mkdir()
        for item in source_dir.iterdir():
            if item.is_symlink() or not item.is_file():
                raise ValueError('Artifact entries must be real files')
            shutil.copyfile(item, frozen / item.name)
        source, record = package.validate(frozen, target, version, revision)
        staged[source.name] = source
        name = 'build-' + platform.replace('_', '-') + '.json'
        (directory / name).write_bytes(record)
        staged[name] = directory / name
        downloads[platform] = [source.name]
        if target.endswith('linux-musl'):
            install = frozen / (package.release_id(revision) + '.tar.gz')
            staged[install.name] = install
    if private_pem is not None:
        identity = package.release_id(revision)
        name = identity + '.manifest.json'
        manifest = signing.sign({'version': identity,
                                 'archive_url': f'{public_base}/{prefix}/releases/{identity}.tar.gz',
                                 'sha256': cdn.file_digest(staged[identity + '.tar.gz'])}, private_pem, public_key)
        (directory / name).write_bytes(manifest)
        staged[name] = directory / name
    hashes = {name: cdn.file_digest(path) for name, path in staged.items()}
    (directory / 'sha256sums').write_bytes(''.join(f'{hashes[name]}  ./{name}\n' for name in sorted(hashes)).encode())
    staged['sha256sums'] = directory / 'sha256sums'
    hashes['sha256sums'] = cdn.file_digest(staged['sha256sums'])
    build = f'{version}-{revision[:12]}-{hashes["sha256sums"][:12]}'
    release_prefix = f'{prefix}/releases/{build}'
    files = {name: {'url': f'{public_base}/{quote(release_prefix)}/{quote(name)}',
                    'sha256': hashes[name], 'size': path.stat().st_size} for name, path in staged.items()}
    latest = {'version': version, 'revision': revision, 'build': build, 'files': files,
              'downloads': {p: [files[n]['url'] for n in names] for p, names in downloads.items()},
              'latest_url': f'{public_base}/{prefix}/latest.json'}
    return staged, latest, release_prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', 'ghostrack-io/ghost-cli'))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    version, revision = package.source()
    prefix = PREFIX
    bucket = os.environ.get('CDN_STORAGE_ZONE') or 'gigahost-apps'
    public_base = os.environ.get('CDN_PUBLIC_BASE') or 'https://apps.ghostrack.io'
    endpoint = os.environ.get('CDN_STORAGE_ENDPOINT') or 'https://sg.storage.bunnycdn.com'
    client = cdn.BunnyHTTPStorage(endpoint, 'dry-run' if args.dry_run else os.environ.get('CDN_STORAGE_PASSWORD'))
    client.object_url(bucket, prefix + '/latest.json')
    with tempfile.TemporaryDirectory(prefix='cli-release-') as temporary:
        staged, latest, release_prefix = prepare(args.packages, Path(temporary), version, revision, prefix, public_base,
                                                None if args.dry_run else os.environ.get('CLI_RELEASE_SIGNING_KEY', ''))
        if args.dry_run:
            for name, item in latest['files'].items():
                print(f'{name} {item["size"]} sha256:{item["sha256"]}')
            print('Unsigned inputs validated; signing and publication were not performed')
            return
        api = GitHub(args.repository, os.environ.get('GITHUB_TOKEN'))
        publish(api, version, revision, staged, latest['files'], tag_prefix='v',
                before_publish=lambda: cdn.publish(client, bucket, prefix, staged, latest, release_prefix,
                                                   signed_manifest=package.release_id(revision) + '.manifest.json'))
        print(f'Published https://github.com/{args.repository}/releases/tag/v{version}')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('Publish failed; rerun the publish job with the same artifacts to reconcile')
