# Handling Secured Configuration

The OpenVTC CLI tool securely stores the sensitive configuration in a Base64 format in the OS secure storage layer of your device. The configuration contains the following information:

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
