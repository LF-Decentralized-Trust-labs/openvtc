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

## Documentation

- [Command Reference](../docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](../docs/relationships-vrcs.md)
