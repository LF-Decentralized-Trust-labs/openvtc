# OpenVTC Tool Commands

Command reference for the OpenVTC CLI tool.

> **Status:** OpenVTC is currently a terminal UI (TUI) application plus a single
> `setup` subcommand. Running `openvtc` with no subcommand launches the TUI,
> where contacts, relationships, tasks, credentials, logs, and config
> export/import are managed interactively. A number of standalone subcommands
> are planned but **not yet implemented** — see
> [Planned commands](#planned-commands-not-yet-implemented).

## Table of Contents

- [Quick Reference](#quick-reference)
- [Global Options](#global-options)
- [Commands](#commands)
  - [openvtc (no subcommand) — launch the TUI](#openvtc-no-subcommand--launch-the-tui)
  - [setup](#openvtc-setup)
- [Profiles](#profiles)
- [Planned commands (not yet implemented)](#planned-commands-not-yet-implemented)

## Quick Reference

| Command         | Description                                            |
| --------------- | ----------------------------------------------------- |
| `openvtc`       | Launch the TUI (status, contacts, relationships, etc.) |
| `openvtc setup` | Run the setup wizard (create or import a profile)      |
| `openvtc --help`    | Display help information                          |
| `openvtc --version` | Print the tool version                            |

## Global Options

These options apply to `openvtc` and its `setup` subcommand:

| Flag                       | Description                                              |
| -------------------------- | ------------------------------------------------------- |
| `-p, --profile <NAME>`     | Use a specific profile configuration (default: `default`) |
| `-u, --unlock-code <CODE>` | Provide the unlock passphrase for an encrypted config   |
| `-h, --help`               | Display help information                                |
| `-V, --version`            | Print the tool version                                  |

> **Warning:** `-u, --unlock-code` exposes the passphrase in the process list
> (`ps`, `/proc`) to other local users. Prefer the interactive prompt on shared
> systems.

**Environment variable:** Set `OPENVTC_CONFIG_PROFILE` to select the profile
globally. If both the env var and `-p/--profile` are set and disagree, the CLI
flag wins and a warning is printed.

**Examples:**

```bash
# Launch the TUI
openvtc

# View help
openvtc --help

# Print the version
openvtc --version

# Launch the TUI for a specific profile
openvtc -p profile-1
```

---

## Commands

## openvtc (no subcommand) — launch the TUI

Running `openvtc` with no subcommand launches the terminal UI. If no
configuration exists for the selected profile, the TUI starts in the setup
wizard automatically (equivalent to `openvtc setup`).

The TUI is where you currently:

- Review status — tool version, your Persona DID(s) and whether they resolve,
  configured authentication/encryption/signing keys, and DIDComm mediator
  connectivity.
- Manage contacts (add/remove known DIDs and aliases).
- Manage relationships and Verifiable Relationship Credentials (VRCs).
- Review tasks and incoming messages.
- View the action/event log.
- Export and (with caveats) restore configuration backups in Settings.

**Usage:**

```bash
openvtc
openvtc -p profile-1
```

---

## openvtc setup

Initialise your OpenVTC environment by creating a profile, generating a Persona
DID, and setting up cryptographic keys. The setup wizard also offers an
**Import / Restore Backup** path for restoring a previously exported
configuration.

**Usage:**

```bash
openvtc setup
```

**Examples:**

Set up the default profile:

```bash
openvtc setup
```

Create (or set up) a named profile:

```bash
openvtc -p profile-1 setup
```

> **Note:** There is no `openvtc setup import` subcommand. To restore an
> exported configuration, run `openvtc setup` and choose the
> **Import / Restore Backup** option in the wizard.

---

## Profiles

OpenVTC supports multiple profiles, allowing you to represent different
identities across various contexts.

- Select a profile with `-p, --profile <NAME>` or the
  `OPENVTC_CONFIG_PROFILE` environment variable.
- Profile names may contain only `[A-Za-z0-9._-]` and must not contain `..`.

```bash
# Per-invocation
openvtc -p profile-1

# Globally, for the current shell session
export OPENVTC_CONFIG_PROFILE=profile-1
openvtc
```

DIDs follow the format `did:webvh:<scid>:<domain>`, for example:

```
did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

---

## Planned commands (not yet implemented)

The following standalone subcommands are part of the intended CLI surface but
are **not implemented yet**. Today the equivalent functionality is reached
through the TUI (launched by running `openvtc` with no subcommand). They are
documented here to capture intent; invoking any of them on the current build
produces a clap "unrecognized subcommand" error.

| Planned command         | Intended description                                 | Today, use instead |
| ----------------------- | ---------------------------------------------------- | ------------------- |
| `openvtc status`        | View current configuration and connectivity          | TUI status view     |
| `openvtc logs`          | Display action/event log history                     | TUI log view        |
| `openvtc export`        | Export settings or PGP keys                          | TUI Settings → Export |
| `openvtc contacts`      | Manage known contacts (add/remove/list)              | TUI contacts panel  |
| `openvtc relationships` | Manage relationships (request/ping/remove/list)      | TUI relationships panel |
| `openvtc tasks`         | Handle outstanding tasks and messages                | TUI tasks panel     |
| `openvtc vrcs`          | Manage Verifiable Relationship Credentials           | TUI VRC views       |

> This table reflects the original design intent. As each command lands, it
> should move up into the [Commands](#commands) section with full flag
> documentation.
