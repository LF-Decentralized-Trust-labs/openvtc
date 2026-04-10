# Contribution Guidelines

Thank you for contributing! Before you contribute, we ask some things of you:

- Please follow our Code of Conduct, the Contributor Covenant. You can find a copy [in this repository](CODE_OF_CONDUCT.md) or under https://www.contributor-covenant.org/
- All Contributors must agree to [a CLA](.github/CLA/INDIVIDUAL.md). When opening a PR, the system will guide you through the process. However, if you contribute on behalf of a legal entity, we ask of you to agree to [a different CLA](.github/CLA/ENTITY.md). In that case, please contact us.


## Getting Started

### Prerequisites

- Rust 1.91.0 or higher — install from [rust-lang.org](https://www.rust-lang.org/learn/get-started)
- Git

### Workspace Layout

This repository is a Cargo workspace. The root `Cargo.toml` defines the following crates:

| Crate | Role |
|---|---|
| `openvtc-lib` | Core library — config, storage, cryptography, DID logic |
| `openvtc-cli` | Primary command-line interface |
| `openvtc-cli2` | Terminal UI (TUI) interface |
| `openvtc-service` | Background service component |
| `robotic-maintainers` | Automated maintenance tooling |

### Building

From the repo root:

```bash
cargo build
```

To build without the OpenPGP card feature:

```bash
cargo build --no-default-features
```

### Testing

```bash
cargo test
```

For a specific crate:

```bash
cargo test -p openvtc-lib
```

### Feature Flags

| Flag | Description | Default |
|---|---|---|
| `openpgp-card` | OpenPGP-compatible hardware token support | Enabled |

### PR Guidelines

- Use conventional commits where possible (e.g. `docs: expand CONTRIBUTING.md`)
- Sign the CLA — GitHub will guide you through this when you open a PR
- Reference the issue your PR addresses (e.g. `Closes #13`)
- If platform-specific behaviour is uncertain, write `> **Note:** TBD — help wanted` rather than documenting incorrect information

### Useful Links

- [README](README.md)
- [Docs index](docs/)
- [Config Data Structure](docs/openvtc-config-data-structure.md)
- [Secured Configuration](docs/secured-configuration-management.md)