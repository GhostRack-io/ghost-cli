#!/usr/bin/env bash
# Validate the public console trust pin embedded by this CLI.
set -euo pipefail

file=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/config/console-host-key.pub}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

[[ -f $file ]] || fail "$file does not exist"
line=$(grep -v '^[[:space:]]*\(#\|$\)' -- "$file" || true)
[[ -n $line && $line != *$'\n'* ]] || fail "$file must hold exactly one public key line"
read -r type blob _ <<<"$line"
[[ $type == ssh-ed25519 ]] || fail "$file must hold an ssh-ed25519 key, not ${type:-nothing}"
[[ $blob != PLACEHOLDER ]] \
    || fail "$file holds the placeholder: put the console's host key there (ssh-keygen -y -f console-ssh-host.key) before a release"
# The blob is the standard base64 of the type's name and the 32-byte key.
decoded=$(base64 --decode 2>/dev/null <<<"$blob" | od -An -tx1 | tr -d ' \n') \
    || fail "$file's key is not base64"
# 00 00 00 0b "ssh-ed25519" 00 00 00 20 and 32 bytes.
[[ $decoded =~ ^0000000b7373682d6564323535313900000020[0-9a-f]{64}$ ]] \
    || fail "$file's key is not an Ed25519 public key"
printf 'console host key %s\n' "$blob"
