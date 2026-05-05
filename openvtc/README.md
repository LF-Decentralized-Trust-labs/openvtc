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

Sensitive configuration (keys, credentials) is stored in the OS secure store:

| Platform | Backend | Requirements |
|----------|---------|--------------|
| macOS | Keychain | Always available |
| Windows | Credential Manager | Always available |
| Linux (desktop) | Secret Service (GNOME Keyring / KDE Wallet) | D-Bus + secret service daemon |
| Linux (headless) | Kernel keyring (`keyutils`) | Available on all Linux kernels ≥ 2.6 |

On headless Linux (servers, containers, CI) where no GUI secret service is
available, the tool automatically falls back to the kernel keyring. No
additional configuration is needed.

If you encounter `Couldn't open OS Secure Store` errors, ensure either:
- A secret service daemon is running (`gnome-keyring-daemon`, `kwalletd`), or
- The `keyutils` kernel module is loaded (`modprobe keyutils`)

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
