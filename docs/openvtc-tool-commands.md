# OpenVTC Tool Commands

Complete command reference for the OpenVTC CLI tool.

## Table of Contents

- [Quick Reference](#quick-reference)
- [Common Patterns](#common-patterns)
- [Global Options](#global-options)
- [Commands](#commands)
  - [setup](#openvtc-setup)
  - [status](#openvtc-status)
  - [logs](#openvtc-logs)
  - [export](#openvtc-export)
  - [contacts](#openvtc-contacts)
  - [relationships](#openvtc-relationships)
  - [tasks](#openvtc-tasks)
  - [vrcs](#openvtc-vrcs)

## Quick Reference

| Command             | Description                                |
| ------------------- | ------------------------------------------ |
| `openvtc setup`         | Initialise environment and create profile  |
| `openvtc status`        | View current configuration                 |
| `openvtc logs`          | Display log history                        |
| `openvtc export`        | Export settings or PGP keys                |
| `openvtc contacts`      | Manage known contacts                      |
| `openvtc relationships` | Manage relationships with other DIDs       |
| `openvtc tasks`         | Handle outstanding tasks and messages      |
| `openvtc vrcs`          | Manage Verifiable Relationship Credentials |

## Common Patterns

### Profile Management

All commands support the `-p, --profile` flag to specify which profile to use:

```bash
openvtc -p <profile-name> <command>
```

**Environment Variable:** Set `OPENVTC_CONFIG_PROFILE` to override the default profile globally.

### Unlock Code

When using an unlock code to protect secured configuration, use `-u, --unlock-code` to avoid repeated prompts:

```bash
openvtc -u <unlock-code> <command>
```

> **Warning:** This exposes your unlock code to the command line history. Avoid using this unless you are using a test profile.

### DID Formats

DIDs should follow the format: `did:webvh:<scid>:<domain>`

Example: `did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com`

---

## Global Options

These options work with all commands:

| Flag                       | Description                          |
| -------------------------- | ------------------------------------ |
| `-p, --profile <NAME>`     | Use a specific profile configuration |
| `-u, --unlock-code <CODE>` | Provide unlock code to skip prompts  |
| `-h, --help`               | Display help information             |

**Examples:**

```bash
# View help for main command
openvtc --help

# View help for specific command
openvtc setup --help

# Use specific profile
openvtc -p profile-1 status

# Use unlock code
openvtc -u MyUnlockCode status
```

---

## Commands

## openvtc setup

Initialise your OpenVTC environment by creating a profile, generating a Persona DID, and setting up cryptographic keys.

**Usage:**

```bash
openvtc setup
openvtc setup import [OPTIONS]
```

**Examples:**

Setup a default profile:

```bash
openvtc setup
```

Create a named profile:

```bash
openvtc -p profile-1 setup
```

### openvtc setup import

Import previously exported OpenVTC settings into a new profile or machine.

**Options:**

| Flag                      | Description                    | Default      |
| ------------------------- | ------------------------------ | ------------ |
| `-f, --file <PATH>`       | Path to exported settings file | `export.openvtc` |
| `-p, --passphrase <PASS>` | Passphrase to decrypt settings | Prompted     |

**Examples:**

Import with default filename from the current directory:

```bash
openvtc setup import
```

Import from specific file:

```bash
openvtc setup import -f ~/Downloads/backup.openvtc
```

Import with passphrase:

```bash
openvtc setup import -f ~/Downloads/backup.openvtc -p MyPassphrase
```

Import to named profile:

```bash
openvtc -p new-profile setup import -f ~/Downloads/backup.openvtc
```

---

## openvtc status

Display current environment and configuration information.

**Usage:**

```bash
openvtc status
```

**Examples:**

Check default profile status:

```bash
openvtc status
```

Check specific profile status:

```bash
openvtc -p profile-1 status
```

---

## openvtc logs

Display log history of actions and events within OpenVTC. Logs include relationship events, contact changes, task operations, vrc operations, and configuration updates.

**Usage:**

```bash
openvtc logs
```

> **Note:** By default, the log maintains up to 100 most recent entries. Older entries are automatically removed. You can update this number by updating the public configuration `limit` property.

**Examples:**

View all log entries:

```bash
openvtc logs
```

View logs for a specific profile:

```bash
openvtc -p profile-1 logs
```

---

## openvtc export

Export settings or cryptographic keys from your environment.

**Usage:**

```bash
openvtc export pgp-keys [OPTIONS]
openvtc export settings [OPTIONS]
```

### openvtc export pgp-keys

Export the primary PGP keys used in your Persona DID for signing, authentication, and decryption.

**Options:**

| Flag                      | Description                          | Required |
| ------------------------- | ------------------------------------ | -------- |
| `-p, --passphrase <PASS>` | Passphrase to protect exported keys  | Yes      |
| `-u, --user-id <ID>`      | PGP User ID: `"Name <email@domain>"` | Yes      |

**Examples:**

Export with interactive prompts:

```bash
openvtc export pgp-keys
```

Export with inline parameters:

```bash
openvtc export pgp-keys -p SecurePass123 -u "John Doe <john@example.com>"
```

Export from specific profile:

```bash
openvtc -p profile-1 export pgp-keys
```

### openvtc export settings

Export settings for importing into another profile or machine.

**Options:**

| Flag                      | Description                    | Default      |
| ------------------------- | ------------------------------ | ------------ |
| `-p, --passphrase <PASS>` | Passphrase to encrypt settings | Prompted     |
| `-f, --file <PATH>`       | Output file path               | `export.openvtc` |

**Examples:**

Export to default file:

```bash
openvtc export settings
```

Export to specific location:

```bash
openvtc export settings -f ~/backups/profile-backup.openvtc
```

Export with inline passphrase:

```bash
openvtc export settings -p SecurePass123 -f ~/backups/profile-backup.openvtc
```

---

## openvtc contacts

Manage your list of known DIDs and their aliases.

**Usage:**

```bash
openvtc contacts add [OPTIONS]
openvtc contacts remove [OPTIONS]
openvtc contacts list
```

### openvtc contacts add

Add a new contact or update an existing one. If the DID already exists, it will be replaced.

**Options:**

| Flag                 | Description          | Required |
| -------------------- | -------------------- | -------- |
| `-d, --did <DID>`    | DID of the contact   | Yes      |
| `-a, --alias <NAME>` | Human-readable alias | No       |
| `-s, --skip`         | Skip DID validation  | No       |

> **Note:** By default, DIDs are verified before adding. Use `--skip` to bypass validation.

**Examples:**

Add contact with verification:

```bash
openvtc contacts add -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com -a "John Doe"
```

Add contact without verification:

```bash
openvtc contacts add -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com -a "John Doe" -s
```

Add contact without alias:

```bash
openvtc contacts add -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

### openvtc contacts remove

Remove a contact by DID or alias.

**Options:**

| Flag                 | Description     | Required     |
| -------------------- | --------------- | ------------ |
| `-d, --did <DID>`    | Remove by DID   | One required |
| `-a, --alias <NAME>` | Remove by alias | One required |

> **Note:** Provide either `--did` or `--alias` to remove contact.

**Examples:**

Remove by DID:

```bash
openvtc contacts remove -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

Remove by alias:

```bash
openvtc contacts remove -a "John Doe"
```

### openvtc contacts list

Display all contacts in the current profile.

**Usage:**

```bash
openvtc contacts list
```

**Examples:**

List all contacts:

```bash
openvtc contacts list
```

---

## openvtc relationships

Manage relationships with other DIDs for secure communication and VRC issuance.

**Usage:**

```bash
openvtc relationships request [OPTIONS]
openvtc relationships ping [OPTIONS]
openvtc relationships remove [OPTIONS]
openvtc relationships list
```

> **See also:** [Relationships and VRCs Guide](./relationships-vrcs.md)

### openvtc relationships request

Send a relationship request to another DID.

**Options:**

| Flag                     | Description                 | Required |
| ------------------------ | --------------------------- | -------- |
| `-d, --respondent <DID>` | Respondent's DID or alias   | Yes      |
| `-a, --alias <NAME>`     | Alias for the respondent    | Yes      |
| `-r, --reason <TEXT>`    | Reason for the relationship | No       |
| `-g, --generate-did`     | Generate a local R-DID      | No       |

> **Tip:** Use `--generate-did` to create a Relationship DID (R-DID) for private channel communication. Without it, your Persona DID (P-DID) will be used.

**Examples:**

Send basic relationship request:

```bash
openvtc relationships request -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com -a "JohnD"
```

Send with reason:

```bash
openvtc relationships request -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com -a "JohnD" -r "Coworker connection"
```

Send with R-DID generation:

```bash
openvtc relationships request -d did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com -a "JohnD" -g
```

Use contact alias:

```bash
openvtc relationships request -d "JohnD" -a "John Doe" -r "Conference attendee"
```

### openvtc relationships ping

Send a trust ping message to test connectivity with an established relationship. The remote recipient must check their messages to respond with a pong.

**Options:**

| Flag                 | Description         | Required |
| -------------------- | ------------------- | -------- |
| `-r, --remote <DID>` | Remote DID or alias | Yes      |

> **Note:** This command requires an established relationship. Check for pong responses using `openvtc tasks interact`.

**Examples:**

Ping by DID:

```bash
openvtc relationships ping -r did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

Ping by alias:

```bash
openvtc relationships ping -r "JohnD"
```

### openvtc relationships remove

Remove an existing relationship and all associated VRCs (both issued and received).

**Options:**

| Flag                 | Description         | Required |
| -------------------- | ------------------- | -------- |
| `-r, --remote <DID>` | Remote DID or alias | Yes      |

> **Warning:** This action cannot be undone. All VRCs associated with this relationship will be permanently deleted.

**Examples:**

Remove by DID:

```bash
openvtc relationships remove -r did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

Remove by alias:

```bash
openvtc relationships remove -r "JohnD"
```

### openvtc relationships list

Display all relationships and their status.

**Usage:**

```bash
openvtc relationships list
```

**Examples:**

List all relationships:

```bash
openvtc relationships list
```

---

## openvtc tasks

Manage outstanding tasks including messages from the mediator, relationship requests, and VRC requests.

**Usage:**

```bash
openvtc tasks list
openvtc tasks fetch
openvtc tasks remove [OPTIONS]
openvtc tasks interact [OPTIONS]
openvtc tasks clear [OPTIONS]
```

### openvtc tasks list

Display all outstanding tasks.

**Usage:**

```bash
openvtc tasks list
```

**Examples:**

List all tasks:

```bash
openvtc tasks list
```

### openvtc tasks fetch

Retrieve new messages and tasks from the mediator.

**Usage:**

```bash
openvtc tasks fetch
```

**Examples:**

Fetch new tasks:

```bash
openvtc tasks fetch
```

### openvtc tasks remove

Remove a specific task by ID.

**Options:**

| Flag              | Description       | Required |
| ----------------- | ----------------- | -------- |
| `-i, --id <UUID>` | Task ID to remove | Yes      |

**Examples:**

Remove specific task:

```bash
openvtc tasks remove --id 50ff0179-6d82-4424-8dab-bdf3b0c24b44
```

### openvtc tasks interact

Interactive CLI manager for fetching and processing tasks (relationship requests, VRC requests, etc.).

**Options:**

| Flag              | Description                       | Required |
| ----------------- | --------------------------------- | -------- |
| `-i, --id <UUID>` | Specific task ID to interact with | No       |

**Examples:**

Enter interactive mode to fetch and process all tasks:

```bash
openvtc tasks interact
```

Interact with specific task:

```bash
openvtc tasks interact --id 50ff0179-6d82-4424-8dab-bdf3b0c24b44
```

openvtcopenvtc tasks clear

Clear all local tasks and optionally remote messages from the mediator.

**Options:**

| Flag       | Description                                            |
| ---------- | ------------------------------------------------------ |
| `--force`  | Skip confirmation prompt                               |
| `--remote` | Remove remote messages from OpenVTC Task Queue on mediator |

> **Warning:** This action cannot be undone. All tasks and messages will be permanently deleted.

**Examples:**

Clear with confirmation:

```bash
openvtc tasks clear
```

Force clear without confirmation:

```bash
openvtc tasks clear --force
```

Clear all tasks including remote messages:

```bash
openvtc tasks clear --remote
```

---

## openvtc vrcs

Manage Verifiable Relationship Credentials (VRCs).

**Usage:**

```bash
openvtc vrcs request
openvtc vrcs list [OPTIONS]
openvtc vrcs show <ID>
openvtc vrcs remove <ID>
```

> **See also:** [Relationships and VRCs Guide](./relationships-vrcs.md#request-verifiable-relationship-credential-vrc)

### openvtc vrcs request

Request a VRC from an established relationship.

**Usage:**

```bash
openvtc vrcs request
```

> **Note:** You must have an [established relationship](./relationships-vrcs.md#establish-relationship) before requesting a VRC. Use interactive prompts to select the relationship and provide credential details.

**Examples:**

Request VRC interactively:

```bash
openvtc vrcs request
```

### openvtc vrcs list

Display all VRCs (both issued and received). Optionally filter by relationship.

**Options:**

| Flag                 | Description                                  | Required |
| -------------------- | -------------------------------------------- | -------- |
| `-r, --remote <DID>` | Show VRCs for a specific remote DID or alias | No       |

**Usage:**

```bash
openvtc vrcs list [OPTIONS]
```

**Examples:**

List all VRCs:

```bash
openvtc vrcs list
```

List VRCs for a specific relationship by DID:

```bash
openvtc vrcs list -r did:webvh:QmbeaiTRfLnkzWvagfAUUuQ8XymXenxNaLVjctqVLafE7u:example.com
```

List VRCs for a specific relationship by alias:

```bash
openvtc vrcs list -r "JohnD"
```

### openvtc vrcs show

Display a specific VRC by ID.

**Usage:**

```bash
openvtc vrcs show <ID>
```

**Examples:**

View specific VRC:

```bash
openvtc vrcs show be85696ebea0e947bde696754be67d640a36b63e1ff9da0c7637c933a6cb469f
```

### openvtc vrcs remove

Remove a VRC from local storage.

**Usage:**

```bash
openvtc vrcs remove <ID>
```

**Examples:**

Remove specific VRC:

```bash
openvtc vrcs remove be85696ebea0e947bde696754be67d640a36b63e1ff9da0c7637c933a6cb469f
```

---
