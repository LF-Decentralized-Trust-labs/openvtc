# openvtc-cli

The original interactive command-line tool for managing OpenVTC identities,
relationships, and verifiable credentials.

## Overview

`openvtc-cli` provides a prompt-driven interface for:

- **Setup** — Create and configure your Persona DID, cryptographic keys, and DIDComm mediator connection
- **Relationships** — Establish, accept, and manage trust relationships with other DID holders
- **VRCs** — Request, issue, and manage Verifiable Relationship Credentials
- **Contacts** — Maintain a local address book of known DIDs
- **Tasks** — View and process pending protocol messages (relationship requests, VRC requests)
- **Export** — Export PGP keys or full configuration backups

## Installation

```bash
cargo install --path openvtc-cli
```

Or build without hardware token support:

```bash
cargo install --path openvtc-cli --no-default-features
```

## Usage

```bash
# Run setup wizard
openvtc setup

# Check environment status
openvtc status

# Use a named profile
openvtc -p my-profile setup

# View pending tasks
openvtc tasks

# Manage relationships
openvtc relationships

# View all commands
openvtc --help
```

## Configuration

Configuration is stored in `~/.config/openvtc/` by default. Override with:

```bash
export OPENVTC_CONFIG_PATH=/custom/path
export OPENVTC_CONFIG_PROFILE=my-profile
```

## Feature Flags

| Flag           | Description                               | Default |
|----------------|-------------------------------------------|---------|
| `openpgp-card` | OpenPGP-compatible hardware token support | Enabled |

## Documentation

- [Command Reference](../docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](../docs/relationships-vrcs.md)
- [Secure Key Management](../docs/secure-key-management.md)
- [Backup and Restore](../docs/backup-restore.md)
