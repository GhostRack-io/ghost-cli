"""Offline publisher regressions: immutable uploads and last-write pointer."""
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
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import BaseHandler, build_opener
from urllib.response import addinfourl
from zipfile import ZipFile

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).parents[1] / "scripts/cdn_release.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class MissingObject(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class Storage:
    def __init__(self):
        self.objects = {}
        self.writes = []
        self.fail_key = None
        self.corrupt_key = None

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise MissingObject()
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, *, Bucket, Key, Body, **metadata):
        if Key == self.fail_key:
            raise RuntimeError("Upload failed")
        self.objects[Key] = Body.read() if hasattr(Body, "read") else Body
        if Key == self.corrupt_key:
            self.objects[Key] += b"corrupt"
        self.writes.append(Key)


class HTTPResponse(io.BytesIO):
    def __init__(self, body=b"", status=200):
        super().__init__(body)
        self.status = status


class HTTPStorageFixture:
    def __init__(self):
        self.objects = {}
        self.requests = []
        self.fail_key = None
        self.failure_status = 403

    def open(self, request, timeout):
        self.requests.append(request)
        key = unquote(urlsplit(request.full_url).path).split("/", 2)[2]
        if key == self.fail_key:
            raise HTTPError(request.full_url, self.failure_status, "Failure", {}, io.BytesIO())
        if request.method == "GET":
            if key not in self.objects:
                raise HTTPError(request.full_url, 404, "Missing", {}, io.BytesIO())
            return HTTPResponse(self.objects[key])
        chunks = []
        while chunk := request.data.read(8192):
            chunks.append(chunk)
        self.objects[key] = b"".join(chunks)
        return HTTPResponse(status=201)


class HTTPTransport(unittest.TestCase):
    def setUp(self):
        self.client = publisher.BunnyHTTPStorage("https://sg.storage.bunnycdn.com", "test-password")
        self.fixture = HTTPStorageFixture()
        self.client.opener = self.fixture

    def test_missing_and_existing_object_digests(self):
        self.assertIsNone(publisher.existing_digest(self.client, "apps", "cli-github/missing.zip"))
        self.fixture.objects["cli-github/present.zip"] = b"package"
        self.assertEqual(publisher.existing_digest(self.client, "apps", "cli-github/present.zip"),
                         hashlib.sha256(b"package").hexdigest())
        self.fixture.fail_key = "cli-github/forbidden.zip"
        with self.assertRaises(publisher.StorageHTTPError) as result:
            publisher.existing_digest(self.client, "apps", self.fixture.fail_key)
        self.assertEqual(result.exception.response["Error"]["Code"], "403")
        self.assertTrue(all(request.get_header("Accesskey") == "test-password"
                            for request in self.fixture.requests))

    def test_put_streams_raw_payload_and_metadata_through_urllib(self):
        connections = []
        class Socket:
            def __init__(self):
                self.sent = []
            def sendall(self, data):
                self.sent.append(bytes(data))
            def makefile(self, mode):
                return io.BytesIO(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
            def close(self):
                pass
        class Connection(http.client.HTTPConnection):
            def __init__(self, host, *, timeout, context=None, check_hostname=None):
                super().__init__(host, timeout=timeout)
                self.captured_socket = Socket()
                connections.append(self)
            def connect(self):
                self.sock = self.captured_socket
        class BoundedStream(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > 8192:
                    raise AssertionError("Upload performed an unbounded read")
                return super().read(size)
        payload = b"\x00\xffraw-package" * 10000
        body = BoundedStream(b"ignored" + payload)
        body.seek(len(b"ignored"))
        # Exercise urllib/http.client's real file streaming without any socket.
        with patch.dict(os.environ, {}, clear=True), patch.object(http.client, "HTTPSConnection", Connection):
            self.client.opener = build_opener(publisher.NoStorageRedirects())
            self.client.put_object(Bucket="apps", Key="cli-github/file #1.zip", Body=body,
                                   ContentType="application/zip", CacheControl="public, immutable")
        self.assertEqual(len(connections), 1)
        connection = connections[0]
        self.assertEqual(connection.host, "sg.storage.bunnycdn.com")
        headers, uploaded = b"".join(connection.captured_socket.sent).split(b"\r\n\r\n", 1)
        self.assertEqual(uploaded, payload)
        self.assertIn(b"PUT /apps/cli-github/file%20%231.zip HTTP/1.1", headers)
        self.assertIn(f"Content-Length: {len(payload)}".encode(), headers)
        self.assertIn(b"Content-Type: application/zip", headers)
        self.assertIn(b"Cache-Control: public, immutable", headers)
        self.assertIn(b"Accesskey: test-password", headers)

    def test_redirect_never_forwards_credentials(self):
        requests = []
        class Redirect(BaseHandler):
            handler_order = 100
            def https_open(self, request):
                requests.append(request)
                response = addinfourl(io.BytesIO(), {"Location": "https://attacker.example/stolen"},
                                      request.full_url, 302)
                response.msg = "Found"
                return response
        self.client.opener = build_opener(publisher.NoStorageRedirects(), Redirect())
        with self.assertRaises(publisher.StorageHTTPError) as result:
            self.client.get_object(Bucket="apps", Key="cli-github/package.zip")
        self.assertEqual(result.exception.response["Error"]["Code"], "302")
        self.assertEqual(len(requests), 1)
        self.assertEqual(urlsplit(requests[0].full_url).hostname, "sg.storage.bunnycdn.com")
        self.assertEqual(requests[0].get_header("Accesskey"), "test-password")

    def test_retries_rewind_upload_and_stop_after_four_attempts(self):
        payloads = []
        def fail_then_succeed(request, timeout):
            payloads.append(request.data.read())
            if len(payloads) < 3:
                raise URLError("connection interrupted")
            return HTTPResponse(status=201)
        with patch.object(self.fixture, "open", side_effect=fail_then_succeed), patch.object(publisher.time, "sleep"):
            self.client.put_object(Bucket="apps", Key="cli-github/package.zip", Body=io.BytesIO(b"same bytes"),
                                   ContentType="application/zip", CacheControl="public, immutable")
        self.assertEqual(payloads, [b"same bytes"] * 3)
        self.fixture.fail_key = "cli-github/package.zip"
        self.fixture.failure_status = 503
        with patch.object(publisher.time, "sleep"), self.assertRaises(publisher.StorageHTTPError):
            self.client.put_object(Bucket="apps", Key=self.fixture.fail_key, Body=b"bytes",
                                   ContentType="application/zip", CacheControl="public, immutable")
        self.assertEqual(len(self.fixture.requests), publisher.MAX_ATTEMPTS)

    def test_invalid_endpoint_zone_and_object_path_are_rejected_before_requests(self):
        for endpoint in ["http://sg.storage.bunnycdn.com", "https://attacker.example",
                         "https://sg-s3.storage.bunnycdn.com", "https://sg.storage.bunnycdn.com/path",
                         "https://user:password@sg.storage.bunnycdn.com", "https://sg.storage.bunnycdn.com:444"]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                publisher.BunnyHTTPStorage(endpoint, "test-password")
        for bucket, key in [("apps/other", "cli-github/file.zip"), ("..", "cli-github/file.zip"),
                            ("apps", "../file.zip"), ("apps", "/cli-github/file.zip"),
                            ("apps", "cli-github//file.zip")]:
            with self.subTest(bucket=bucket, key=key), self.assertRaises(ValueError):
                self.client.get_object(Bucket=bucket, Key=key)
        self.assertEqual(self.fixture.requests, [])

    def test_public_verification_retries_without_storage_credentials(self):
        url = "https://cdn.example/cli-github/latest.json?build=version"
        expected = hashlib.sha256(b"latest").hexdigest()
        missing = HTTPError(url, 404, "Not yet replicated", {}, io.BytesIO())
        with patch.object(publisher, "urlopen", side_effect=[missing, HTTPResponse(b"stale"), HTTPResponse(b"latest")]) as fetch, \
                patch.object(publisher.time, "sleep"):
            publisher.verify_public(url, expected)
        self.assertEqual(fetch.call_count, 3)
        for call in fetch.call_args_list:
            self.assertEqual(call.args[0].full_url, url)
            self.assertIsNone(call.args[0].get_header("Accesskey"))
        with patch.object(publisher, "urlopen", side_effect=lambda *args, **kwargs: HTTPResponse(b"stale")) as fetch, \
                patch.object(publisher.time, "sleep"), self.assertRaisesRegex(ValueError, "checksum mismatch"):
            publisher.verify_public(url, expected)
        self.assertEqual(fetch.call_count, publisher.MAX_ATTEMPTS)


if __name__ == "__main__":
    unittest.main()
