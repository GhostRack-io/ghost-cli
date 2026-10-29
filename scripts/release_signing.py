#!/usr/bin/env python3
"""Ed25519 installer manifests using the pinned public release key and OpenSSL 3."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

PUBLIC_KEY = Path(__file__).resolve().parents[1] / 'config/release-public.pem'
ED25519_SPKI = bytes.fromhex('302a300506032b6570032100')


def openssl(*arguments):
    # Never inherit Actions credentials, OpenSSL configuration overrides or keys.
    try:
        result = subprocess.run(['openssl', *map(str, arguments)],
                                env={'PATH': os.defpath, 'LANG': 'C'},
                                capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Release cryptography failed') from None
    if result.returncode:
        raise ValueError('Release cryptography failed')
    return result.stdout


def public_der(path):
    der = openssl('pkey', '-pubin', '-in', path, '-outform', 'DER')
    if len(der) != 44 or not der.startswith(ED25519_SPKI):
        raise ValueError('Release public key must be Ed25519')
    return der


def canonical(release):
    if (set(release) != {'version', 'archive_url', 'sha256'} or
            not isinstance(release['version'], str) or
            not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}', release['version']) or
            not isinstance(release['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', release['sha256']) or
            not isinstance(release['archive_url'], str) or not release['archive_url'].startswith('https://')):
        raise ValueError('Invalid signed release metadata')
    # Same bytes as jq -cS .release, including its final newline.
    return (json.dumps(release, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def verify(manifest, public_key=PUBLIC_KEY):
    if set(manifest) != {'release', 'signature'}:
        raise ValueError('Invalid signed manifest fields')
    try:
        signature = base64.b64decode(manifest['signature'], validate=True)
    except (ValueError, TypeError):
        raise ValueError('Invalid release signature encoding') from None
    if len(signature) != 64 or base64.b64encode(signature).decode() != manifest['signature']:
        raise ValueError('Invalid release signature length or encoding')
    public_der(public_key)
    with tempfile.TemporaryDirectory(prefix='ghost-verify-') as temporary:
        root = Path(temporary)
        (root / 'message').write_bytes(canonical(manifest['release']))
        (root / 'signature').write_bytes(signature)
        openssl('pkeyutl', '-verify', '-pubin', '-inkey', public_key, '-rawin',
                '-in', root / 'message', '-sigfile', root / 'signature')


def sign(release, private_pem, public_key=PUBLIC_KEY):
    if not openssl('version').startswith(b'OpenSSL 3.'):
        raise ValueError('OpenSSL 3 is required')
    message = canonical(release)
    expected = public_der(public_key)
    if not isinstance(private_pem, str) or not private_pem or len(private_pem) > 16384:
        raise ValueError('Set CLI_RELEASE_SIGNING_KEY to the trusted Ed25519 PEM key')
    with tempfile.TemporaryDirectory(prefix='ghost-sign-') as temporary:
        root = Path(temporary)
        key = root / 'key.pem'
        fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(private_pem)
        # A password protected or malformed key fails without an interactive prompt.
        actual = openssl('pkey', '-in', key, '-passin', 'pass:', '-pubout', '-outform', 'DER')
        if actual != expected:
            raise ValueError('Release signer does not match the pinned public key')
        (root / 'message').write_bytes(message)
        signature = openssl('pkeyutl', '-sign', '-inkey', key, '-passin', 'pass:', '-rawin', '-in', root / 'message')
    manifest = {'release': release, 'signature': base64.b64encode(signature).decode()}
    verify(manifest, public_key)
    return (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()
