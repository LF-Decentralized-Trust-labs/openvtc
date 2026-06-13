# did-git-sign

A standalone CLI tool that signs git commits using DID Ed25519 keys managed by a
[Verifiable Trust Agent (VTA)](https://github.com/LF-Decentralized-Trust-labs/verifiable-trust-infrastructure).
It acts as a git SSH signing proxy — no private key material ever touches disk.

## How It Works

Git supports pluggable signing programs via `gpg.ssh.program`. When you commit,
git calls `did-git-sign` with the commit data on stdin. The tool:

1. Loads its config (`.did-git-sign.json`) and retrieves the VTA credential from the OS keyring
2. Authenticates with the VTA (or reuses a cached token)
3. Fetches the Ed25519 signing key from the VTA on-the-fly
4. Produces an SSH signature (PROTOCOL.sshsig format) and writes it to stdout
5. Zeroizes the key material from memory

Your DID verification method ID (e.g. `did:webvh:abc:example.com#key-0`) is used
as the git `user.email`, linking every commit to your decentralized identity.

## Prerequisites

- A running VTA instance with your DID and keys provisioned
- A **VTA credential bundle** (base64url-encoded string issued by the VTA)
- Your **VTA signing key ID** (the opaque key identifier in the VTA)
- Your **DID#key-id** (e.g. `did:webvh:abc123:example.com#key-0`)

## Install

From the workspace root:

```bash
cargo install --path did-git-sign
```

## Setup

### Per-repository

```bash
did-git-sign init \
  --credential "eyJkaWQiOi..." \
  --key-id "your-vta-key-id" \
  --did-key-id "did:webvh:abc123:example.com#key-0" \
  --name "Your Name"
```

This creates `.did-git-sign.json` in the current directory and configures the
local git repo.

### Global (all repositories)

```bash
did-git-sign init --global \
  --credential "eyJkaWQiOi..." \
  --key-id "your-vta-key-id" \
  --did-key-id "did:webvh:abc123:example.com#key-0" \
  --name "Your Name"
```

This saves config to `~/.config/did-git-sign/config.json` and sets global git
config.

### Options

| Flag | Description |
|------|-------------|
| `--credential` | Base64url-encoded VTA credential bundle (required) |
| `--key-id` | VTA key ID for your Ed25519 signing key (required) |
| `--did-key-id` | DID verification method ID to use as git `user.email` (required) |
| `--name` | Git `user.name` (optional) |
| `--vta-url` | Override VTA URL if not present in credential bundle (optional) |
| `--global` | Use global git config instead of per-repo (optional) |

### What `init` configures

The `init` command performs the following:

1. **Saves config** to `.did-git-sign.json` (local) or `~/.config/did-git-sign/config.json` (global) — contains only `key_id`, `did_key_id`, and `user_name`
2. **Stores VTA credentials** (URL, DIDs, private key) in the OS keyring (macOS Keychain / Linux Secret Service)
3. **Verifies VTA connectivity** by authenticating and fetching the signing key
4. **Configures git:**
   - `gpg.format = ssh`
   - `gpg.ssh.program = did-git-sign`
   - `gpg.ssh.defaultKeyFile = <config path>`
   - `commit.gpgsign = true`
   - `user.email = <DID#key-id>`
   - `user.name = <name>` (if provided)
5. **Creates an `allowed_signers` file** for signature verification and sets `gpg.ssh.allowedSignersFile`

## Usage

After setup, commits are signed automatically:

```bash
git commit -m "my signed commit"
```

Verify signatures:

```bash
git log --show-signature
```

Check your configuration:

```bash
did-git-sign status
```

### Selecting which community persona signs

With more than one provisioned persona, you can choose which one signs without
re-running `init`. At sign time the signing key is resolved in this order:

1. The `DID_GIT_SIGN_KEY` environment variable (per-invocation override).
2. The `did-git-sign.key` per-repo git config setting.
3. The `did_key_id` in the config file git points at (the `init` default).

The value is the persona's `did:webvh:…#key-N`. It must have credentials stored
in the keyring (i.e. you ran `init` for that persona); otherwise signing fails
with a clear message rather than silently signing as a different persona.

```bash
# One commit as a specific persona:
DID_GIT_SIGN_KEY=did:webvh:abc:example.com#key-1 git commit -m "…"

# Pin a persona for this repository:
git config did-git-sign.key did:webvh:abc:example.com#key-1
```

## Security Model

- **No key material on disk** — the VTA credential private key is stored in the
  OS keyring, and the Ed25519 signing key is fetched from the VTA at sign-time
  and held only in memory.
- **Token caching** — the VTA access token is cached in the OS keyring to avoid
  re-authentication on every commit. Tokens are validated with a 30-second
  safety margin before reuse.
- **Zeroization** — signing key material is zeroized immediately after use via
  the `zeroize` crate.
- **`DID_GIT_SIGN_SSH_KEYGEN` override is test-only.** The path to `ssh-keygen`
  used for the verify / find-principals / check-novalidate delegation paths
  can be overridden via this environment variable so test fixtures can point
  at a mock binary. **Do not set it in production.** An attacker with write
  access to your environment could redirect signature verification to a
  binary that always returns success and silently accept forged signatures.
  The override has no effect on the *signing* path, which never invokes
  `ssh-keygen`.

## Architecture

```
git commit
    |
    v
git calls: did-git-sign -Y sign -f .did-git-sign.json -n git
    |                                                (stdin: commit data)
    v
did-git-sign:
    1. Load config from .did-git-sign.json (key_id + did_key_id only)
    2. Load VTA credentials from OS keyring
    3. Authenticate with VTA (or use cached token from keyring)
    4. Fetch Ed25519 key: VTA.get_key_secret(key_id)
    5. Sign commit data (PROTOCOL.sshsig format)
    6. Output SSH signature to stdout
    7. Zeroize key material
    |
    v
git stores signature in commit
```

## Config File Format

The `.did-git-sign.json` file contains only your DID identity:

```json
{
  "did_key_id": "did:webvh:abc123:example.com#key-0",
  "user_name": "Your Name"
}
```

**No VTA credentials or key identifiers are stored on disk.** All VTA
configuration and sensitive material is stored in the OS keyring under the
service name `did-git-sign`:

| Keyring Entry | Contents |
|---------------|----------|
| `{did_key_id}:vta` | VTA URL, VTA DID, credential DID, credential private key, signing key ID |
| `{did_key_id}:token` | Cached VTA access token and expiry |
