"""Fixed-origin GitHub draft publisher; public release is the final mutation."""
import json
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

class APIError(Exception):
    def __init__(self, status=None):
        self.status = status
        super().__init__(f'GitHub request failed (HTTP {status})' if status else 'GitHub request failed; rerun to reconcile')


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, repository, token):
        if not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+', repository) or repository.split('/')[1] in ('.', '..'):
            raise ValueError('Repository must be owner/repository')
        if not token or any(c in token for c in '\r\n'):
            raise ValueError('Set GH_TOKEN or GITHUB_TOKEN outside Git')
        self.repository = repository
        self.token = token
        self.opener = build_opener(NoRedirects())

    def request(self, method, path, value=None, asset=None):
        # Callers provide API-relative paths only. Upload URLs from responses
        # are deliberately ignored: authenticated requests have fixed origins.
        if not path.startswith('/') or any(c in path for c in '\r\n#'):
            raise ValueError('Invalid API path')
        origin = 'https://uploads.github.com' if asset is not None else 'https://api.github.com'
        headers = {'Authorization': f'Bearer {self.token}', 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'release-publisher'}
        body = None
        if value is not None:
            body = (json.dumps(value, sort_keys=True) + "\n").encode()
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = str(len(body))
        if asset is not None:
            body = asset.open('rb')
            headers['Content-Type'] = 'application/octet-stream'
            headers['Content-Length'] = str(asset.stat().st_size)
        try:
            with self.opener.open(Request(origin + path, data=body, headers=headers, method=method), timeout=120) as response:
                if not 200 <= response.status < 300:
                    raise APIError(response.status)
                return json.load(response)
        except HTTPError as error:
            status = error.code
            error.close()
            raise APIError(status) from None
        except (URLError, HTTPException, TimeoutError, ConnectionError, OSError):
            raise APIError() from None
        finally:
            if asset is not None:
                body.close()

    @property
    def base(self):
        return '/repos/' + self.repository

    def pages(self, path):
        # Bound malformed or endlessly changing pagination rather than mutate
        # after an incomplete enumeration.
        for page in range(1, 1001):
            values = self.request('GET', f'{path}?per_page=100&page={page}')
            if not isinstance(values, list):
                raise ValueError('Invalid GitHub collection')
            yield from values
            if len(values) < 100:
                return
        raise ValueError('GitHub pagination limit exceeded')


def tag_commit(api, tag):
    try:
        obj = api.request('GET', f'{api.base}/git/ref/tags/{quote(tag, safe="")}')['object']
    except APIError as error:
        if error.status == 404:
            return None
        raise
    for _ in range(10):
        if obj.get('type') == 'commit':
            return obj['sha']
        if obj.get('type') != 'tag' or not re.fullmatch(r'[0-9a-f]{40}', obj.get('sha', '')):
            break
        obj = api.request('GET', f'{api.base}/git/tags/{obj["sha"]}')['object']
    raise ValueError('Invalid or excessively nested release tag')


def check_source(api, tag, revision, release=None):
    if api.request('GET', f'{api.base}/commits/{revision}').get('sha') != revision:
        raise ValueError('Selected source commit does not exist')
    actual = tag_commit(api, tag)
    if actual is not None and actual != revision:
        raise ValueError('Release tag points to a different source commit')
    if release is not None and actual is None:
        if not release.get('draft') or release.get('target_commitish') != revision:
            raise ValueError('Release has no matching tag or exact draft source commit')
    return actual


def asset_set(api, release, expected, complete):
    assets = list(api.pages(f'{api.base}/releases/{release["id"]}/assets'))
    seen = set()
    for asset in assets:
        name = asset.get('name')
        if name not in expected or name in seen:
            raise ValueError('Unexpected or duplicate release asset')
        seen.add(name)
        item = expected[name]
        if (asset.get('state') != 'uploaded' or asset.get('size') != item['size'] or
                asset.get('digest') != 'sha256:' + item['sha256']):
            raise ValueError('Existing release asset does not match verified bytes')
    if complete and seen != set(expected):
        raise ValueError('Release asset set is incomplete')
    return seen


def publish(api, version, revision, staged, expected, notes='', *, tag_prefix='v', before_publish=lambda: None):
    tag = tag_prefix + version
    check_source(api, tag, revision)
    releases = [r for r in api.pages(f'{api.base}/releases') if r.get('tag_name') == tag]
    if len(releases) > 1:
        raise ValueError('Multiple releases use the selected tag')
    release = releases[0] if releases else None
    if release is not None:
        check_source(api, tag, revision, release)
        seen = asset_set(api, release, expected, complete=not release['draft'])
        if not release['draft']:
            before_publish()
            return release
    else:
        release = api.request('POST', f'{api.base}/releases', {
            'tag_name': tag, 'target_commitish': revision, 'name': tag, 'body': notes, 'draft': True})
        if not release.get('draft') or release.get('tag_name') != tag:
            raise ValueError('GitHub did not create the expected draft')
        check_source(api, tag, revision, release)
        seen = asset_set(api, release, expected, complete=False)
    release_id = release.get('id')
    if not isinstance(release_id, int) or release_id <= 0:
        raise ValueError('Invalid GitHub release id')
    for name, path in staged.items():
        if name not in seen:
            api.request('POST', f'{api.base}/releases/{release_id}/assets?name={quote(name, safe="")}', asset=path)
    asset_set(api, release, expected, complete=True)
    check_source(api, tag, revision, release)
    before_publish()
    check_source(api, tag, revision, release)
    release = api.request('PATCH', f'{api.base}/releases/{release_id}', {'draft': False})
    if release.get('draft') is not False or release.get('tag_name') != tag:
        raise ValueError('GitHub did not publish the expected release')
    if check_source(api, tag, revision, release) != revision:
        raise ValueError('Published tag is missing')
    asset_set(api, release, expected, complete=True)
    return release
