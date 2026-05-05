# OpenVTC — Project Guidelines

## Project overview

OpenVTC (Open Verifiable Trust Communities) is a reference implementation
on top of the verifiable trust infrastructure. This repository hosts:

- `openvtc` — the CLI (ratatui TUI). Primary user-facing tool.
- `openvtc-core` — shared library code used by the CLI.
- `did-git-sign` — standalone DID-based git commit signing proxy.

The heavy lifting of the verifiable trust infrastructure (VTA, key
management, credential protocols, DIDComm services) lives in a separate
repository:

  https://github.com/OpenVTC/verifiable-trust-infrastructure

When something needs changing at the protocol or infrastructure layer,
that repo is usually the correct target — not this one. This repo should
stay focused on the CLI / UX / configuration surface.

## did:webvh interactions

When working with `did:webvh` identifiers, **always use the `didwebvh-rs`
library's APIs** for any DID ⇄ URL mapping, parsing, or formatting. Do not
hand-roll string manipulation for these conversions.

The library already provides:

- `didwebvh_rs::url::WebVHURL::parse_url(&url::Url)` — convert an HTTP URL
  into a `WebVHURL` (handles scheme/host/port/path correctly).
- `WebVHURL::parse_did_url(&str)` — parse a `did:webvh:...` string.
- `WebVHURL::to_did_base()` — emit the canonical `did:webvh:{SCID}:…` form
  with colon-separated path segments and `%3A`-encoded ports.
- `WebVHURL::get_http_url(...)`, `get_http_whois_url()`, `get_http_files_url()`
  — derive resolvable HTTP URLs from a DID.

Hand-rolling these conversions has already caused one bug: a manual
`format!("{host}{path}")` left a URL path slash inside the DID
(`did:webvh:{SCID}:r2.ic3.dev/vincent`) where the spec requires a colon,
producing a DID that resolved to the wrong URL. See
`openvtc-core/src/config/did.rs::normalize_webvh_url` for the canonical
entry point that now delegates to the library.

If the library appears to be missing a capability, prefer opening an issue
or extending the library over reimplementing it locally.
