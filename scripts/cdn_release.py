#!/usr/bin/env python3
"""Publish immutable release objects; advance the CDN pointer after public verification."""
import hashlib
from http.client import HTTPException
import io
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

RETRY_STATUSES = {408, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4


def digest(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        value.update(chunk)
    return value.hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return digest(stream)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def validate_url(url, name):
    parsed = urlsplit(url)
    if (any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url) or
            parsed.scheme != "https" or not parsed.hostname or parsed.port == 0 or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError(f"{name} must be an HTTPS URL without credentials, query, or fragment")
    return url.rstrip("/")


class StorageHTTPError(Exception):
    def __init__(self, status):
        # Preserve the missing-object convention used by the S3 publisher, but
        # never retain response bodies or request headers containing secrets.
        self.response = {"Error": {"Code": str(status)}}
        super().__init__(f"Storage API request failed (HTTP {status})")


class NoStorageRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # AccessKey must never be forwarded to a redirect destination.
        return None


class BunnyHTTPStorage:
    """Small S3-compatible get/put adapter for Bunny's HTTP Storage API."""

    def __init__(self, endpoint, password):
        self.endpoint = validate_url(endpoint, "Bunny HTTP endpoint")
        parsed = urlsplit(self.endpoint)
        if (parsed.path or parsed.port not in (None, 443) or
                not re.fullmatch(r"(?:[a-z]{2,3}\.)?storage\.bunnycdn\.com", parsed.hostname or "")):
            raise ValueError("Bunny HTTP endpoint must be a regional Bunny Storage HTTPS origin")
        if not password or "\r" in password or "\n" in password:
            raise ValueError("Set a valid CDN_STORAGE_PASSWORD outside Git")
        self.password = password
        self.opener = build_opener(NoStorageRedirects())

    def object_url(self, bucket, key):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", bucket):
            raise ValueError("Storage zone must be a single safe path component")
        parts = key.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("Invalid storage object path")
        return f"{self.endpoint}/{bucket}/" + "/".join(quote(part, safe="") for part in parts)

    def request(self, method, bucket, key, body=None, headers=None):
        url = self.object_url(bucket, key)
        headers = {**(headers or {}), "AccessKey": self.password, "Accept-Encoding": "identity"}
        start = body.tell() if body is not None else None
        for attempt in range(MAX_ATTEMPTS):
            if body is not None:
                body.seek(start)
            try:
                # urllib streams file-like data in bounded chunks when an
                # explicit Content-Length is present. Redirects are disabled.
                response = self.opener.open(Request(url, data=body, headers=headers, method=method), timeout=120)
                if 200 <= response.status < 300:
                    return response
                status = response.status
                response.close()
                raise StorageHTTPError(status)
            except HTTPError as error:
                status = error.code
                error.close()
                if status not in RETRY_STATUSES or attempt == MAX_ATTEMPTS - 1:
                    raise StorageHTTPError(status) from None
            except StorageHTTPError as error:
                if int(error.response["Error"]["Code"]) not in RETRY_STATUSES or attempt == MAX_ATTEMPTS - 1:
                    raise
            except (URLError, TimeoutError, ConnectionError, HTTPException):
                if attempt == MAX_ATTEMPTS - 1:
                    raise
            time.sleep(2 ** attempt)

    def get_object(self, *, Bucket, Key):
        return {"Body": self.request("GET", Bucket, Key)}

    def put_object(self, *, Bucket, Key, Body, ContentType, CacheControl):
        body = io.BytesIO(Body) if isinstance(Body, bytes) else Body
        try:
            start = body.tell()
            body.seek(0, io.SEEK_END)
            length = body.tell() - start
            body.seek(start)
        except (AttributeError, OSError):
            raise ValueError("HTTP upload body must be a seekable binary stream") from None
        response = self.request("PUT", Bucket, Key, body,
                                {"Content-Length": str(length), "Content-Type": ContentType,
                                 "Cache-Control": CacheControl})
        response.close()


def existing_digest(client, bucket, key):
    try:
        body = client.get_object(Bucket=bucket, Key=key)["Body"]
    except Exception as error:
        response = getattr(error, "response", {})
        if response.get("Error", {}).get("Code") in ("NoSuchKey", "NotFound", "404"):
            return None
        raise
    try:
        return digest(body)
    finally:
        body.close()


def verify_public(url, expected):
    # Verify the actual download bytes through the public CDN before advertising
    # them. No storage credentials are attached to CDN requests.
    for attempt in range(MAX_ATTEMPTS):
        try:
            with urlopen(Request(url, headers={"Accept-Encoding": "identity"}), timeout=120) as response:
                if digest(response) != expected:
                    raise ValueError("Public CDN download checksum mismatch")
            return
        except HTTPError as error:
            status = error.code
            error.close()
            if status not in RETRY_STATUSES | {404} or attempt == MAX_ATTEMPTS - 1:
                raise
        except (URLError, TimeoutError, ConnectionError, HTTPException, ValueError):
            if attempt == MAX_ATTEMPTS - 1:
                raise
        time.sleep(2 ** attempt)


def content_type(name):
    if name.endswith(".zip"):
        return "application/zip"
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".dmg"):
        return "application/x-apple-diskimage"
    if name.endswith(".deb"):
        return "application/vnd.debian.binary-package"
    return "application/octet-stream"


def publish(client, bucket, prefix, uploads, latest, release_prefix, public_check=verify_public, signed_manifest=None):
    locations = {f'{release_prefix}/{name}': (name, latest['files'][name]['url']) for name in uploads}
    if signed_manifest is not None:
        if prefix != 'cli-github' or signed_manifest not in uploads:
            raise ValueError('Invalid signed CLI channel')
        manifest = json.loads(uploads[signed_manifest].read_bytes())
        identity = manifest['release']['version']
        archive = identity + '.tar.gz'
        if signed_manifest != identity + '.manifest.json' or archive not in uploads:
            raise ValueError('Missing signed installer assets')
        public_base = latest['latest_url'].removesuffix('/' + prefix + '/latest.json')
        for name in (archive, signed_manifest):
            key = f'{prefix}/releases/{name}'
            locations[key] = (name, f'{public_base}/{key}')
    existing = {}
    # Check every content-derived object AND flat immutable installer alias
    # before the first write, including conflicts late in the allowlist.
    for key, (name, _) in locations.items():
        existing[key] = existing_digest(client, bucket, key)
        if existing[key] not in (None, latest['files'][name]['sha256']):
            raise ValueError('Immutable build already exists with different bytes; use a new source revision')
    for key, (name, url) in locations.items():
        value = uploads[name]
        if existing[key] is None:
            body = value.open('rb') if isinstance(value, Path) else io.BytesIO(value)
            with body:
                client.put_object(Bucket=bucket, Key=key, Body=body,
                                  ContentType=content_type(name),
                                  CacheControl='public, max-age=31536000, immutable')
        if existing_digest(client, bucket, key) != latest['files'][name]['sha256']:
            raise ValueError('Uploaded package verification failed')
        public_check(url, latest['files'][name]['sha256'])
        print(f'Verified {name}')
    def pointer(key, value, url):
        client.put_object(Bucket=bucket, Key=key, Body=value, ContentType='application/json',
                          CacheControl='no-cache, max-age=60')
        expected = hashlib.sha256(value).hexdigest()
        if existing_digest(client, bucket, key) != expected:
            raise ValueError('Latest pointer verification failed')
        public_check(url + '?build=' + quote(latest['build']), expected)
    pointer(f'{prefix}/latest.json', json_bytes(latest), latest['latest_url'])
    if signed_manifest is not None:
        # This pointer is the installer's commit point and always the LAST write.
        pointer(f'{prefix}/releases/manifest.json', uploads[signed_manifest].read_bytes(),
                f'{public_base}/{prefix}/releases/manifest.json')
    print(f"Published build {latest['build']}")
