# Contribution Guidelines

Thank you for contributing to OpenVTC.

This repository is a Rust workspace with multiple crates and binaries. The
sections below are intended to help new contributors get oriented quickly,
build the right target, and prepare focused pull requests.

## Before You Open a Pull Request

- Follow the Contributor Covenant Code of Conduct.
- Be prepared to complete the contributor license agreement flow when opening a
  pull request. If you are contributing on behalf of a legal entity, contact
  the maintainers so they can point you to the correct agreement.
- Keep pull requests small and scoped to one change when possible.
- Include the issue number or problem statement in the PR description.

## Workspace Layout

The workspace currently includes these crates:

- `openvtc-lib` (`openvtc` package): shared library code for configuration,
  DIDs, DIDComm message handling, relationships, VRCs, tasks, and crypto
  helpers.
- `openvtc-cli`: the primary CLI binary published as `openvtc`.
- `openvtc-cli2`: alternate TUI-oriented CLI binary published as `openvtc2`.
- `openvtc-service`: service binary for maintainer and protocol automation
  workflows.
- `robotic-maintainers`: automation and example maintainer workflow tooling.

If you are unsure where to start:

- user-facing CLI setup and command behavior usually lives in `openvtc-cli` or
  `openvtc-cli2`
- shared business logic usually belongs in `openvtc-lib`
- service/operator behavior usually belongs in `openvtc-service`

## Prerequisites

- Rust `1.91.0` or newer. The workspace `Cargo.toml` is the source of truth for
  the toolchain version.
- Git
- Optional hardware token support if you want to exercise the `openpgp-card`
  feature in real environments.

## Build and Test

From the repository root:

```bash
cargo build
cargo test
```

Target a single package while iterating on a change:

```bash
cargo test -p openvtc
cargo test -p openvtc-cli
cargo test -p openvtc-cli2
cargo test -p openvtc-service
```

Build or test without default hardware-token support:

```bash
cargo build --no-default-features
cargo test -p openvtc --no-default-features
```

Run the primary CLI from source:

```bash
cargo run -p openvtc-cli -- --help
```

## Cross-Platform Configuration Notes

OpenVTC uses two environment variables during local development:

- `OPENVTC_CONFIG_PROFILE`
- `OPENVTC_CONFIG_PATH`

The implementation currently resolves the default config directory from
`dirs::home_dir()` and then appends `/.config/openvtc/` before choosing
`config.json` or `config-<profile>.json`. If you need a predictable path during
development, set `OPENVTC_CONFIG_PATH` explicitly instead of relying on shell-
specific home-directory conventions.

Examples:

```bash
export OPENVTC_CONFIG_PROFILE=profile-1
export OPENVTC_CONFIG_PATH="$HOME/.config/openvtc"
```

```powershell
$env:OPENVTC_CONFIG_PROFILE = "profile-1"
$env:OPENVTC_CONFIG_PATH = "$HOME/.config/openvtc"
```

For persistent shell configuration, use the mechanism appropriate for your
shell or operating system rather than assuming Bash or Zsh startup files.

## Documentation Pointers

Helpful starting points:

- `README.md` for project overview, setup, and command entry points
- `docs/openvtc-tool-commands.md` for command reference
- `docs/openvtc-config-data-structure.md` for config model details
- `docs/secured-configuration-management.md` for secure-storage behavior
- `docs/relationships-vrcs.md` for relationship and VRC flows

## Pull Request Expectations

- Describe the problem being solved and the user or developer impact.
- List the packages or docs you changed.
- Include the commands you ran to validate the change.
- Call out platform-specific verification when editing setup or configuration
  documentation.
- Avoid unrelated formatting or drive-by rewrites in the same PR.
