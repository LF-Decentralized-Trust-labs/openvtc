# openvtc

A terminal user interface (TUI) for managing OpenVTC identities, relationships,
and verifiable credentials. Built with [ratatui](https://ratatui.rs/).

## Overview

`openvtc` is the OpenVTC client, providing a rich TUI experience with:

- **Setup wizard** — Guided multi-step setup flow with real-time feedback
- **Main dashboard** — View relationships, contacts, tasks, and VRCs at a glance
- **DIDComm messaging** — Live WebSocket-based message handling with visual status
- **Keyboard-driven navigation** — Fast interaction without leaving the terminal

## Architecture

The application follows an actor model with unidirectional data flow:

```
┌──────────┐  Actions   ┌──────────────┐  State   ┌───────────┐
│ UI Layer ├───────────→│ StateHandler ├─────────→│ UI Layer  │
│ (render) │            │  (business)  │          │ (render)  │
└──────────┘            └──────────────┘          └───────────┘
```

- **`UiManager`** renders state and captures key events as `Action` variants
- **`StateHandler`** processes actions, performs DID/DIDComm operations, emits `State` updates
- **Graceful shutdown** via broadcast channels and OS signal handling

## Installation

```bash
cargo install --path openvtc
```

Or build without hardware token support:

```bash
cargo install --path openvtc --no-default-features
```

## Usage

```bash
# Start with default profile (auto-detects setup vs main mode)
openvtc

# Force setup wizard
openvtc setup

# Use a named profile
openvtc -p my-profile
```

## Configuration

- Default location: `~/.config/openvtc/`
- Override: `OPENVTC_CONFIG_PATH` and `OPENVTC_CONFIG_PROFILE` environment variables

### Secure Storage

A profile lives in two halves: a **config file** on disk
(`~/.config/openvtc/config.json`) and its **secret key material** — the BIP32
seed or VTA credential bundle — in an OS credential store. Both are needed.
Copying one without the other produces `No matching credential found` at
startup; `openvtc health` says so explicitly.

| Platform | Backend | Durable? | Requirements |
|----------|---------|----------|--------------|
| macOS | Keychain | Yes | Always available |
| Windows | Credential Manager | Yes | Always available |
| Linux (desktop) | Secret Service (GNOME Keyring / KWallet / KeePassXC) | Yes | D-Bus session + a keyring daemon |
| Linux, no Secret Service, profile **with** a passphrase or token | Encrypted file in `~/.config/openvtc/secrets/` (mode `0600`) | Yes | none |
| Linux, no Secret Service, profile **without** either | Kernel keyring (`keyutils`) | **No — lost on reboot** | none |

On Linux, OpenVTC tries Secret Service first. If no daemon answers (headless
servers, containers, CI, SSH sessions with no `DBUS_SESSION_BUS_ADDRESS`), it
uses the encrypted-file store — but **only for a profile whose secret is
actually encrypted**, meaning one protected by a passphrase or a hardware
token. An unprotected profile's seed is never written to disk in the clear; it
stays in the kernel keyring, and OpenVTC warns you that it is there.

> **The kernel keyring does not persist.** The backend
> [documents itself](https://docs.rs/linux-keyutils-keyring-store) as RAM-only:
> the session keyring dies at logout, and the persistent keyring expires after
> `/proc/sys/kernel/keys/persistent_keyring_expiry` (3 days by default). A
> profile stored there is lost on reboot and **cannot be recovered**. If
> OpenVTC warns that a profile is stored this way, do one of:
>
> 1. **Set a passphrase** — Settings → Protection. The secret moves to the
>    encrypted-file store and survives reboots.
> 2. **Run a Secret Service daemon** — `gnome-keyring-daemon`, `kwalletd`,
>    KeePassXC, or `oo7-daemon`.
> 3. **Export a backup** — Settings → Export Config — and keep it elsewhere.

Override the automatic choice with `OPENVTC_SECURE_STORE` (Linux only):

| Value | Effect |
|-------|--------|
| `auto` (default) | Secret Service, else encrypted file over kernel keyring |
| `secret-service` | Require Secret Service; fail if none is reachable |
| `file` | Require the encrypted-file store; refuses an unprotected profile |
| `keyutils` | Force the kernel keyring (volatile — testing only) |

#### When the secure store fails

`openvtc health` reports which store is in use, whether this profile's
credential is present, and how long it will survive — and it runs even when the
profile cannot be decrypted, which is when you need it. On a startup failure,
OpenVTC also writes the full diagnosis to
`~/.config/openvtc/last-startup-failure.txt`; attach that to a bug report.

To look at the entry yourself:

```bash
# macOS
security find-generic-password -s openvtc -a default
# Linux (Secret Service)
secret-tool search service openvtc username default
# Linux (kernel keyring)
keyctl show @us; keyctl show @s
# Linux (encrypted file)
ls -l ~/.config/openvtc/secrets/
# Windows
cmdkey /list | findstr openvtc
```

## Feature Flags

| Flag           | Description                               | Default |
|----------------|-------------------------------------------|---------|
| `openpgp-card` | OpenPGP-compatible hardware token support | Enabled |

## Troubleshooting

### Debug Logging

The TUI captures stdout/stderr for rendering, so standard `RUST_LOG` output
is not visible. To enable file-based debug logging, set `OPENVTC_DEBUG_LOG`
to a file path:

```bash
OPENVTC_DEBUG_LOG=/tmp/openvtc.log openvtc
```

This writes timestamped tracing output at `debug` level to the specified file.
For finer control, combine with `RUST_LOG`:

```bash
# Only log openvtc and DIDComm service at debug, everything else at warn
OPENVTC_DEBUG_LOG=/tmp/openvtc.log \
  RUST_LOG="warn,openvtc=debug,openvtc_core=debug,affinidi_messaging_didcomm_service=debug" \
  openvtc
```

Useful patterns to look for in the logs:
- `built listener configs` — shows how many DIDComm listeners were created at startup
- `registered listener` — shows each listener's ID and state
- `rapid disconnect cycling detected` — indicates a WebSocket reconnect loop
- `sending DIDComm message` — tracks outbound message routing

### Common Issues

**WebSocket reconnect loop** — If the activity log shows repeated
"Listener 'persona' disconnected / restarting" messages, check:
1. Only one instance of openvtc is running for this profile (`ps aux | grep openvtc`)
2. Network connectivity to the mediator is stable
3. Debug logs for duplicate listener registration

**Configuration not found** — Ensure `~/.config/openvtc/` exists or set
`OPENVTC_CONFIG_PATH`. Run `openvtc setup` to create initial configuration.

## Documentation

- [Command Reference](../docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](../docs/relationships-vrcs.md)
