# ghost

The GhostRack customer CLI. Run `ghost --help` for commands.

Build with the pinned Rust toolchain: `cargo build --locked --release`.
Run checks with `cargo test --locked --workspace`.

The shared customer API crate lives in `crates/client-api`.
Both packages are licensed under Apache-2.0; see LICENSE.

## Releases

Download native packages from [GitHub Releases](https://github.com/ghostrack-io/ghost-cli/releases/latest)
or the [CDN catalog](https://apps.ghostrack.io/cli-github/latest.json).
The CLI releases Action builds and checks Linux x64 (static musl), Windows x64,
macOS arm64 and macOS x64. Matching `v<package version>` tags publish;
manual runs default to checking only. Select `publish` to publish both destinations.

Set the Actions secrets `CDN_STORAGE_PASSWORD` and `CLI_RELEASE_SIGNING_KEY`
(the trusted Ed25519 private key in PEM format), and allow this repository to use them.
Optional Actions variables: `CDN_STORAGE_ENDPOINT` (default
`https://sg.storage.bunnycdn.com`), `CDN_STORAGE_ZONE` (`gigahost-apps`),
`CDN_PUBLIC_BASE` (`https://apps.ghostrack.io`). The channel folder is `cli-github`.
Only the publish job receives credentials and `GITHUB_TOKEN` with `contents: write`.

Python 3.10+ runs `scripts/package-release.py` after the pinned Rust build. It
checks the native executable's version/help, architecture, static Linux linkage,
source identity, public console pin, license and archive contents. Each archive
contains only `bin/ghost` (`bin/ghost.exe` on Windows),
`lib/gigahost/cli-release`, `LICENSE` and `build.json`. Extract the whole archive
into one directory and add its `bin` directory to `PATH`; keep `lib` beside `bin`.
The release identity comes from the source commit's UTC timestamp and hash and
is identical across the four native targets. The Action runs the extracted
binary's version/help checks with that release marker in place.

Publication uses identical frozen assets for GitHub and CDN. It verifies a GitHub
draft, immutable CDN objects and public downloads, writes and verifies
`latest.json`, then writes the signed
[installer manifest](https://apps.ghostrack.io/cli-github/releases/manifest.json)
last on the CDN, then publishes GitHub. The Linux installer archive contains only
`VERSION` and `ghost`; its binary is identical to the native Linux package.
Signing verifies the secret against `config/release-public.pem` before any upload. Rerun the failed publish job
with the same artifacts to resume; never rebuild to replace conflicting assets.
An identical published GitHub release still reconciles CDN state. CDN can succeed
before final GitHub publication fails, and the catalog may advance before the
signed pointer; publication across providers is not atomic.
`python scripts/publish-release.py --packages artifacts/downloads --dry-run`
validates unsigned inputs without credentials or uploads from the clean selected
source checkout; it does not sign. An Ubuntu checks job runs all release Python
tests with real ephemeral OpenSSL 3 keys before publication can run.
