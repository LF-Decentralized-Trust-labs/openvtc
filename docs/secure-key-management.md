# OpenVTC Secure Key Management Design

The OpenVTC CLI tool requires the use of many secret keys for it to work; at a minimum
the following keys are required:

- **Persona DID**
  - `SIGNING_KEY`: Primary signing key used to sign Verified Credentials (VCs) and
    Verifiable Presentations (VPs).
  - `AUTHENTICATION_KEY`: Proof of ownership of the private key associated with
    this public key.
    - This key is used to identify this account. Can be used for SSH access,
      challenge/response services, etc.
  - `ENCRYPTION_KEY`: Used to encrypt/decrypt data.

- **DID Management (WebVH Management Keys)**
  - N x pre-rolled LogEntry update keys (where N = # of keys defined in WebVH Parameters)
  - Any other key material you wish to place into the DID Document
- **Relationship Credentials**
  - As you create relationships with other entities, a specific relationship DID
    is created for each relationship with it's own separate set of keys

All of the above is linked back to the `Persona DID`.

OpenVTC is designed to be used with physical hardware tokens, such as those made by Nitrokey or Yubikey.

These tokens **MUST** support the openpgp-card protocol.

## Derivation Paths

| Path          | Description                                    |
| ------------- | ---------------------------------------------- |
| `m/0'/0'/`    | Reserved for OpenVTC management keys               |
| `m/1'/0'/`    | Reserved for Persona DID Keys                  |
| `m/2'/1'/`    | Reserved for Persona DID WebVH Management keys |
| `m/3'/1'/1'/` | Reserved for Relationship DID keys             |

## Initial `Public Identity` Secure Key Setup

```mermaid
---
config:
  look: handDrawn
  theme: default
  layout: elk
---
flowchart TB
    A(["Setup"]) --> useRecovery["Use a Recovery Phrase?"]
    B{"Use Existing PGP Secrets?"} -- No --> BIP32["Create BIP32 root"]
    B --> curve25519{"Curve25519 only?"}
    BIP32 --> subId2[["Generate Curve25519 Secrets"]] & n7["If new BIP32, then show BIP39 recovery phrase"]
    existKeys[("PGP Private Keys")] --> subId1[["Import PGP Keys"]]
    curve25519 -- No --> BIP32
    curve25519 -- Yes --> subId1
    privateKeys["Private Key Information"] --> E{"Use openpgp-card?"}
    E -- Yes --> exportCard["Add Secrets to card"]
    exportCard --> signingKey["Signing Key"] & encryptKey["Encryption Key"] & authKey["Authentication Key"] & enableMFA["Enable MFA on Signing Key"]
    encryptSecrets[["Encrypt Secrets"]] --> saveKeyRing["Save to OS Secure Store"]
    enableMFA --> encryptSecrets
    saveKeyRing --> n2(["END"])
    E -- No --> n3["Select unlock phrase"]
    n3 --> seedHash["Generate Seed Hash from unlock phrase"]
    seedHash --> encryptSecrets
    useRecovery -- No --> B
    useRecovery --> n4["Validate Recovery Phrase"]
    n5["BIP39 Recovery Phrase"] --> n4
    n4 -- Failed --> n6(["Failed to Validate Recovery Phrase"])
    n4 -- Success --> B
    subId1 --> BIP32
    n7 --> BIP39["Show BIP39 recovery phrase"]
    subId2 --> privateKeys
    useRecovery@{ shape: diam}
    n7@{ shape: diam}
    privateKeys@{ shape: h-cyl}
    signingKey@{ shape: internal-storage}
    encryptKey@{ shape: internal-storage}
    authKey@{ shape: internal-storage}
    enableMFA@{ shape: subproc}
    seedHash@{ shape: subproc}
    n4@{ shape: diam}
    n5@{ shape: manual-input}
    style existKeys color:#D50000,stroke:#D50000
    style privateKeys stroke:#000000,fill:#D50000,color:#FFFFFF
    style n2 stroke:#00C853,fill:#C8E6C9
    style n6 stroke:#D50000,fill:#FFCDD2
    style BIP39 stroke:#00C853,color:#00C853
    linkStyle 2 stroke:#000000,fill:none

```

### Starting Key Space mapping

OpenVTC derives key paths from a BIP32 root. Common starting key paths are:

- Persona DID Path `m/1'/0'/`
  - `m/1'/0'/0'` :: Persona DID Signing Key
  - `m/1'/0'/1'` :: Persona DID Authentication Key
  - `m/1'/0'/2'` :: Persona DID Encryption Key

- WebVH DID Management Path `m/2'/1'`
  - `m/2'/1'/<n>'` :: Pre-rolled update keys for WebVH LogEntries

## CLI Tool unlock

Whenever the CLI tool executes, it needs to unlock the secret key material so it
can use DIDComm to interact with other services.

```mermaid
---
config:
  look: handDrawn
  layout: dagre
  theme: default
---
flowchart TB
    A(["Setup"]) --> PGPCard{"Using openpgp-card?"}
    PGPCard -- No --> checkPhrase{"Match Unlock Hash?"}
    secureStorage["OS Secure Storage"] --> DecryptSecrets{"Decrypt Secrets"}
    PGPCard -- Yes --> DecryptSecrets
    checkPhrase -- Success --> DecryptSecrets
    DecryptSecrets -- Success --> n2(["CLI Tool Unlocked"])
    DecryptSecrets -- Failure --> failedUnlock(["Failed to Unlock"])
    checkPhrase -- Failed --> failedUnlock
    unlockPhrase["Unlock Phrase"] --> checkPhrase
    secureStorage@{ shape: cyl}
    unlockPhrase@{ shape: manual-input}
```

### Configuration management

There are three configuration stores for the OpenVTC CLI tool:

1. SecuredConfig :: OS Secure Storage (Key material)
2. PrivateConfig :: Encrypted sensitive configuration (relationships and DID contacts,
   etc.)
   - Uses `m/0'/0'/0'` as the derived key for the encryption of PrivateConfig
3. PublicConfig :: Non-sensitive configuration, contains the encrypted PrivateConfig

## Signing Verifiable Credential

Whenever the CLI tool needs to create and sign a verifiable credential, it must
use the `SIGNING_KEY`.

If you are using a hardware token, it is **_STRONGLY_** recommended to enable MFA
(e.g., touch activation) on the signing key.

```mermaid
---
config:
  look: handDrawn
  layout: dagre
  theme: default
---
flowchart TB
    A(["Sign VC"]) --> openpgp-card{"Using opencard-pgp?"}
    openpgp-card -- Yes --> cardUnlock["Touch Card"]
    cardUnlock -- Success --> cardSign["Sign on Device"]
    cardUnlock -- Fail --> FailureState(["Failed Result"])
    openpgp-card -- No --> enterUnlockPhrase{"Unlock Phrase?"}
    unlockPhrase["Unlock Phrase"] --> enterUnlockPhrase
    enterUnlockPhrase -- Success --> signCredential["Sign Credential"]
    enterUnlockPhrase -- Fail --> FailureState
    cardSign --> publishVC["Publish signed VC"]
    signCredential --> publishVC
    publishVC --> success(["Success"])
    cardUnlock@{ shape: diam}
    unlockPhrase@{ shape: manual-input}
    publishVC@{ shape: subproc}
    style FailureState stroke:#D50000,fill:#FFCDD2
    style success stroke:#00C853,fill:#C8E6C9
```

## Relationship DID Key Management

When you create a relationship with another entity, a new DID may be created.

A relationship DID is a DID:PEER with two keys:

1. Verification Key (Ed25519)
2. Encryption Key (X25519)

The key path for relationship DIDs is:

- `m/3'/1'/1'/N` :: Relationship DID key space

This allows for some flexibility in the future if the derivation paths need to be
changed.
