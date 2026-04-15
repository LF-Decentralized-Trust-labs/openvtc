# openvtc-cli2

A terminal user interface (TUI) for managing OpenVTC identities, relationships,
and verifiable credentials. Built with [ratatui](https://ratatui.rs/).

## Overview

`openvtc-cli2` is the next-generation OpenVTC client, providing a rich TUI
experience with:

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
cargo install --path openvtc-cli2
```

Or build without hardware token support:

```bash
cargo install --path openvtc-cli2 --no-default-features
```

## Usage

```bash
# Start with default profile (auto-detects setup vs main mode)
openvtc2

# Force setup wizard
openvtc2 setup

# Use a named profile
openvtc2 -p my-profile
```

## Configuration

Uses the same configuration as `openvtc-cli`:

- Default location: `~/.config/openvtc/`
- Override: `OPENVTC_CONFIG_PATH` and `OPENVTC_CONFIG_PROFILE` environment variables

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
OPENVTC_DEBUG_LOG=/tmp/openvtc.log openvtc2
```

This writes timestamped tracing output at `debug` level to the specified file.
For finer control, combine with `RUST_LOG`:

```bash
# Only log openvtc and DIDComm service at debug, everything else at warn
OPENVTC_DEBUG_LOG=/tmp/openvtc.log \
  RUST_LOG="warn,openvtc=debug,openvtc_cli2=debug,affinidi_messaging_didcomm_service=debug" \
  openvtc2
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
`OPENVTC_CONFIG_PATH`. Run `openvtc2 setup` to create initial configuration.

## Documentation

- [Command Reference](../docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](../docs/relationships-vrcs.md)
