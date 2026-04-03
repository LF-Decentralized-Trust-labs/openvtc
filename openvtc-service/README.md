# OpenVTC Service

A background service that listens for DIDComm messages via a mediator and
responds to community protocol requests (e.g. maintainer list queries) on
behalf of the Open Source Trust Community.

## Prerequisites

- Rust 1.91.0 or higher (Install [Rust](https://rust-lang.org/learn/get-started/))
- A `did:webvh` DID for the service, with its cryptographic keys — use the
  [didwebvh-rs crate](https://crates.io/crates/didwebvh-rs) to create these
- A DIDComm mediator endpoint for message routing

## Getting Started

1. Clone this repository.
2. Copy the example config and fill in your DID, mediator, and secrets:

   ```sh
   cp openvtc-service/conf/config.json-example openvtc-service/conf/config.json
   ```

3. Run the service from the workspace root:

   ```sh
   cargo run -p openvtc-service --release
   ```

For available options:

```sh
cargo run -p openvtc-service --release -- --help
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c`, `--config <PATH>` | `conf/config.json` | Path to the JSON configuration file |

## Configuration

The service loads its configuration from a JSON file (default: `conf/config.json`).
See [`conf/config.json-example`](conf/config.json-example) for the full structure.

> **Warning:** This file contains private key material. Never commit real secrets
> to version control. Restrict file permissions (`chmod 600`) and rotate keys if
> they are ever exposed.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `maintainers` | `[{ alias, did }]` | List of community maintainers with their display name and `did:webvh` identifier |
| `mediator` | `string` | DID of the DIDComm mediator used for message routing |
| `our_did` | `string` | The service's own `did:webvh` identifier |
| `secrets` | `[Secret]` | Cryptographic key material for the service DID (Ed25519 for signing, X25519 for encryption) |

Each entry in `secrets` follows the `JsonWebKey2020` format:

```json
{
  "id": "did:webvh:...:example.com#key-0",
  "type": "JsonWebKey2020",
  "privateKeyJwk": {
    "crv": "Ed25519",
    "d": "<base64url-encoded-private-key>",
    "kty": "OKP",
    "x": "<base64url-encoded-public-key>"
  }
}
```

Two secrets are required:
- **`#key-0`** — Ed25519 key for signing and authentication
- **`#key-1`** — X25519 key for message encryption/decryption

## Logging

The service uses the [`tracing`](https://crates.io/crates/tracing) framework
with an environment filter. Set the `RUST_LOG` variable to control verbosity:

```sh
# Default (warnings and errors only)
cargo run -p openvtc-service --release

# Info level — shows handled requests
RUST_LOG=info cargo run -p openvtc-service --release

# Debug level for this crate only
RUST_LOG=openvtc_service=debug cargo run -p openvtc-service --release
```

### What the log levels mean

| Level | What is logged |
|-------|----------------|
| `info` | Startup, maintainer list requests handled |
| `warn` | Message pickup errors, unsupported message types, missing sender/recipient addresses |
| `error` | Configuration file parsing failures |

## Runtime Behavior

On startup the service:

1. Loads configuration from the JSON file.
2. Creates an ATM (Affinidi Trust Messaging) profile and registers with the mediator.
3. Enters an infinite message loop, polling the mediator for new DIDComm messages.

### Message loop

- **Maintainer list request** (`https://kernel.org/maintainers/1.0/list`) —
  responds with the configured maintainer list and logs at `info`.
- **Status messages** (`https://didcomm.org/messagepickup/3.0/status`) —
  silently ignored (normal protocol traffic).
- **Any other message type** — logged as a warning and discarded.

### Error handling

When the mediator connection produces an error, the service logs a warning and
retries on the next loop iteration. There is no exponential backoff — the loop
runs continuously. If you see repeated errors, check mediator connectivity and
configuration.

## Protocol Context

The service uses protocol message type URIs defined as constants in `openvtc-lib`:

- **Request:** `https://kernel.org/maintainers/1.0/list`
- **Response:** `https://kernel.org/maintainers/1.0/list/response`

These are fixed protocol identifiers for the maintainer list protocol, not
deployment-specific values. The ATM profile is registered under the
`kernel.org` community namespace.
