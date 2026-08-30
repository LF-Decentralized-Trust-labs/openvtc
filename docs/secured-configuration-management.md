# Handling Secured Configuration

The OpenVTC CLI tool securely stores the sensitive configuration in a Base64 format in the OS secure storage layer of your device. The configuration contains the following information:

On macOS this uses the system Keychain. On Linux this uses the system keyring (for example GNOME Keyring or KWallet). On Windows, secrets are stored using the Windows Credential Manager via the `keyring` crate integration used by OpenVTC.

- BIP32 seed used to create the cryptographic keys to generate Decentralised Identifiers (DIDs), specifically your Persona DID.

- Key Info containing the following details:
  - Derivation path for BIP32 or the multi-encoded private key of the DID when configured with a hardware token.

  - Date and time of when the key info was first created.

OpenVTC stores the configuration details in the OS secure storage in three different ways:

## Hardware Token

During setup, the tool can utilise a hardware token that implements the OpenPGP card standard to securely store the cryptographic key pair associated with your Persona DID.

After generating the key pair, the tool performs the following steps:

1. Generates a random 32-byte seed, which serves as the random session key.

2. Uses the seed to create an AES-256 key and encrypt the configuration data using AES-GCM, which includes the BIP32 seed and key information.

3. Encrypts the seed using the public key generated for your DID, producing an Encrypted Session Key (ESK).

The ESK and the encrypted configuration are securely stored in the OS secure storage, ensuring that sensitive key material remains protected.

When the tool later needs to retrieve the configuration:

1. It requires the presence of the hardware token to decrypt the ESK using the private key on the token.

2. Uses the decrypted session key to create an AES-256 key.

3. Decrypt the encrypted configuration using the AES-256 key using AES-GCM, allowing access to the BIP32 seed and key information.

## Unlock Code

If you choose not to use a hardware token during the setup, you can nominate your unlock code to protect your configuration.

Using the unlock code, the tool performs the following steps:

1. It hashes the unlock code entered by the user.

2. Creates an AES-256 key from the hashed unlock code.

3. Uses the AES-256 key to encrypt the configuration data using AES-GCM, which includes the BIP32 seed and key information.

The encrypted configuration is securely stored in the OS’s secure storage, ensuring that sensitive key material remains protected.

When the tool later needs to retrieve the configuration:

1. It requires the user to enter the unlock code.

2. Hashes the unlock code and creates an AES-256 key.

3. Uses the AES-256 key to decrypt the encrypted configuration using AES-GCM, allowing access to the BIP32 seed and key information.

## Plaintext

The plaintext option stores the configuration in plaintext format in the OS's secure storage. The plaintext option is not part of the OpenVTC setup by default.

## Storage format (and why it is one line)

Whichever of the three protections is in use, the value handed to the OS
credential store is the same shape: a single-line, compact JSON envelope whose
payloads are all BASE64URL. `openvtc-core/src/config/secured_config.rs`
(`encode_blob`) is the only place that writes it, and it refuses to emit a
secret containing a line break, a control character, a backslash, or any
non-ASCII byte.

That is a hard requirement, not a style preference. gnome-keyring writes an
item's secret into `~/.local/share/keyrings/*.keyring` verbatim, but reads it
back through `GKeyFile` *unescaping*. A secret with a raw newline in it
therefore comes back as extra lines of the keyring file, and the daemon fails
to parse the file at all:

```text
keyring was in an invalid or unrecognized format: .../Default_keyring.keyring
```

The blast radius is the whole collection, not just the OpenVTC item — every
other secret in the user's login keyring becomes unreadable too.

### Recovering a keyring OpenVTC has already corrupted

Releases before this fix stored the envelope pretty-printed, so on a Secret
Service backend the first save would break the login keyring. The data is
orphaned, not destroyed. To recover:

1. Stop the daemon so it cannot rewrite anything under you:
   `systemctl --user stop gnome-keyring-daemon.service` (or log out).
2. Copy the whole `~/.local/share/keyrings/` directory somewhere safe before
   touching it.
3. Look at the `default` file — a small pointer naming the active keyring. If
   the unlock prompt was answered at some point after the breakage, the answer
   created a *new* empty keyring and repointed `default` at it; note the
   original name so you can point it back.
4. In the original `.keyring` file, find the OpenVTC item's secret: it is the
   value that spills across several lines instead of one. Either join it back
   into a single line or delete that item's block entirely — the rest of the
   file parses again either way.
5. Point `default` back at the original keyring, restart the daemon, and
   confirm with `secret-tool search --all service openvtc`.

If the OpenVTC item itself cannot be salvaged, the profile's secret half is
gone and the config file alone will not start it — see
[backup-restore.md](backup-restore.md) for what that costs and what can be
recovered from the VTA.
