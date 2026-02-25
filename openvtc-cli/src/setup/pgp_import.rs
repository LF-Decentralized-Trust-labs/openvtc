/*! Handles the import of PGP Key Material
*   
*   Annoyingly PGP spec is convoluted and treats the primary key differently to the sub keys
*   So need to handle primary and subkeys separately
*/

use crate::{
    CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED,
    setup::{KeyInfo, KeyPurpose},
};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, MappedLocalTime, TimeDelta, TimeZone, Utc};
use console::{StyledObject, style};
use dialoguer::{Confirm, Editor, Input, Password, theme::ColorfulTheme};
use openvtc::config::secured_config::KeySourceMaterial;
use pgp::{
    composed::{Deserializable, SignedSecretKey, SignedSecretSubKey},
    crypto::ecdh,
    packet::KeyFlags,
    types::{KeyDetails, PlainSecretParams, SecretParams},
};
use regex::Regex;
use zeroize::Zeroize;

/// Holds imported PGP Keys
#[derive(Default)]
pub struct PGPKeys {
    /// PGP Signing Key (Must be Ed25519)
    pub signing: Option<KeyInfo>,

    /// PGP Encryption Key (Must be X25519)
    pub encryption: Option<KeyInfo>,

    /// PGP Authentication Key (Must be Ed25519)
    pub authentication: Option<KeyInfo>,
}

impl PGPKeys {
    /// Did we import any keys?
    pub fn is_empty(&self) -> bool {
        self.signing.is_none() && self.encryption.is_none() && self.authentication.is_none()
    }

    /// Confirms via the terminal if a valid imported key should be used for a specific purpose
    pub fn confirm_key_use(&mut self, key: KeyInfo, purpose: KeyPurpose) {
        // Change the expiry of the key if needed?
        let key = modify_key_expiry(&key, &purpose);

        match purpose {
            KeyPurpose::Signing => {
                if self.signing.is_none()
                    && Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Use this key for Signing?")
                        .default(true)
                        .interact()
                        .unwrap_or(false)
                {
                    self.signing = Some(key);
                }
            }
            KeyPurpose::Authentication => {
                if self.authentication.is_none()
                    && Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Use this key for Authentication?")
                        .default(true)
                        .interact()
                        .unwrap_or(false)
                {
                    self.authentication = Some(key);
                }
            }
            KeyPurpose::Encryption => {
                if self.encryption.is_none()
                    && Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Use this key for Encryption?")
                        .default(true)
                        .interact()
                        .unwrap_or(false)
                {
                    self.encryption = Some(key)
                }
            }
            _ => {
                // can safely ignore unknown purposes
            }
        }
    }

    pub fn import_sub_key(&mut self, key: &mut SignedSecretSubKey, password: &str) {
        println!();

        if unlock_pgp_sub_key(&mut key.key, password).is_err() {
            return;
        }

        let Some(signature) = key.signatures.first() else {
            println!(
                "{}",
                style("No key signature found for this subkey").color256(CLI_RED)
            );
            return;
        };

        show_key_purpose(signature.key_flags());
        // Print some key info
        print!("{} ", style("Created time:").color256(CLI_BLUE));
        let created = if let Some(created) = signature.created() {
            print!("{}", style(created).color256(CLI_GREEN));
            created.to_owned()
        } else {
            println!("{}", style("N/A").color256(CLI_ORANGE));
            println!("{}", style("WARNING: A key must have a creation time, as it is missing we assume new creation time of now").color256(CLI_ORANGE));
            Utc::now()
        };

        print!(" {} ", style("Expires?:").color256(CLI_BLUE));
        print!(
            "{}",
            style(get_expiry_date(&created, signature.key_expiration_time()))
        );
        if let Some(expiry) = signature.key_expiration_time() {
            print!("{}", style(created + *expiry).color256(CLI_GREEN));
        } else {
            print!("{}", style("Never").color256(CLI_GREEN));
        }
        println!();

        let Ok(secret) = check_crypto_algo_type(key.secret_params(), signature.key_flags()) else {
            return;
        };

        let ki = KeyInfo {
            source: KeySourceMaterial::Imported {
                seed: secret.get_private_keymultibase().unwrap(),
            },
            secret,
            expiry: signature.key_expiration_time().map(|e| e.to_owned()),
            created,
        };

        let kp = if signature.key_flags().sign() {
            KeyPurpose::Signing
        } else if signature.key_flags().authentication() {
            KeyPurpose::Authentication
        } else if signature.key_flags().encrypt_comms() || signature.key_flags().encrypt_storage() {
            KeyPurpose::Encryption
        } else {
            println!("{}", style("Unknown key purpose (expected Signing, Authentication or Encryption/Decryption!").color256(CLI_RED));
            return;
        };

        self.confirm_key_use(ki, kp);
    }
}

/// Handles terminal input of a PGP Key
pub fn terminal_input_pgp_key() -> Result<PGPKeys> {
    println!(
        "{}",
        style("You will be prompted to enter pre-created PGP private key details.")
            .color256(CLI_BLUE)
    );
    println!();
    println!(
        "{}",
        style("The key format must look like the following:").color256(CLI_BLUE)
    );
    println!(
        "\t{}",
        style("-----BEGIN PGP PRIVATE KEY BLOCK-----").color256(CLI_PURPLE)
    );
    println!(
        "\n\t{}",
        style("<PRIVATE KEY MATERIAL>").color256(CLI_PURPLE)
    );
    println!(
        "\t{}\n",
        style("-----END PGP PRIVATE KEY BLOCK-----").color256(CLI_PURPLE)
    );
    println!(
        "{}",
        style("This PGP private key must be the export of a PGP key with the following details:")
            .color256(CLI_BLUE)
    );
    println!(
        "\t{}",
        style("1. Signing and Authentication keys must be Ed25519").color256(CLI_BLUE)
    );
    println!(
        "\t{}",
        style("2. Encryption key must be X25519").color256(CLI_BLUE)
    );
    println!();
    println!(
        "\t{}",
        style("NOTE: If a key is invalid for any reason, it will be ignored").color256(CLI_ORANGE)
    );
    println!(
        "\t{}",
        style("NOTE: Key Expiry will be honored, key rotation is up to the user to manage")
            .color256(CLI_ORANGE)
    );
    println!();
    println!(
        "\t{}",
        style("Any missing key information will be auto-generated from the BIP32 root")
            .color256(CLI_ORANGE)
    );

    println!();
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Continue?")
        .default(true)
        .interact()
        .unwrap_or(false)
    {
        bail!("PGP key import aborted by user")
    }

    let input: String = match Editor::new()
        .edit("Paste your PGP private key here")
        .context("An error occurred importing PGP private key")?
    {
        Some(input) => input,
        _ => {
            bail!("Aborted PGP key import");
        }
    };

    let imported = check_pgp_keys(&input)?;

    println!();
    println!("{}", style("Imported PGP Key Status:").color256(CLI_BLUE));
    if imported.is_empty() {
        println!(
            "  {}",
            style("No keys were imported from PGP!").color256(CLI_PURPLE)
        );
    } else {
        if let Some(key) = &imported.signing {
            println!(
                "  {} {}",
                style("Signing Public Key:").color256(CLI_BLUE),
                style(key.secret.get_public_keymultibase()?).color256(CLI_GREEN)
            );
        }

        if let Some(key) = &imported.authentication {
            println!(
                "  {} {}",
                style("Authentication Public Key:").color256(CLI_BLUE),
                style(key.secret.get_public_keymultibase()?).color256(CLI_GREEN)
            );
        }

        if let Some(key) = &imported.encryption {
            println!(
                "  {} {}",
                style("Encryption Public Key:").color256(CLI_BLUE),
                style(key.secret.get_public_keymultibase()?).color256(CLI_GREEN)
            );
        }
    }
    Ok(imported)
}

/// Imports PGP Key structure from a export String
/// Returns a PGPKeys struct
pub fn check_pgp_keys(raw_key: &str) -> Result<PGPKeys> {
    let (mut keys, _) = SignedSecretKey::from_string(raw_key)?;

    // Try unlocking the key
    let mut password: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter PGP Key Passphrase (if no passphrase, leave blank)")
        .allow_empty_password(true)
        .interact()
        .unwrap_or_default();

    unlock_pgp_key(&mut keys.primary_key, &password)?;

    let mut imported = PGPKeys::default();

    // Process the PGP Primary Key and assign it to the right slot
    let (primary_flags, ki) = extract_primary_key_details(&keys)?;

    let kp = if primary_flags.sign() {
        KeyPurpose::Signing
    } else if primary_flags.authentication() {
        KeyPurpose::Authentication
    } else if primary_flags.encrypt_comms() || primary_flags.encrypt_storage() {
        KeyPurpose::Encryption
    } else {
        println!(
            "{}",
            style(
                "Unknown key purpose - expected Signing, Authentication or Encryption/Decryption!"
            )
            .color256(CLI_RED)
        );
        bail!(
            "Unknown key purpose found - expected Signing, Authentication or Encryption/Decryption"
        );
    };

    imported.confirm_key_use(ki, kp);

    for k in keys.secret_subkeys.iter_mut() {
        imported.import_sub_key(k, &password);
    }

    password.zeroize();
    Ok(imported)
}

/// Extract important key info from the primary key
fn extract_primary_key_details(primary_key: &SignedSecretKey) -> Result<(KeyFlags, KeyInfo)> {
    let Some(user) = primary_key.details.users.first() else {
        println!(
            "{}",
            style("Couldn't find a valid user in the PGP primary key!").color256(CLI_RED)
        );
        bail!("Invalid User in the PGP primary key!");
    };

    print!("{} ", style("Primary Key User:").color256(CLI_BLUE));
    if let Some(user) = user.id.as_str() {
        println!("{}", style(user).color256(CLI_GREEN));
    } else {
        println!("{}", style("UNKNOWN").color256(CLI_ORANGE));
    }
    println!();

    let Some(signature) = user.signatures.first() else {
        println!(
            "{}",
            style("No key signature found for the primary key").color256(CLI_RED)
        );
        bail!("No key signature found for the primary key!");
    };

    // Display the Key Purpose
    show_key_purpose(signature.key_flags());

    // Print some key info
    print!("{} ", style("Created time:").color256(CLI_BLUE));
    let created = if let Some(created) = signature.created() {
        print!("{}", style(created).color256(CLI_GREEN));
        created.to_owned()
    } else {
        print!("{}", style("N/A").color256(CLI_ORANGE));
        println!("\n{}", style("WARNING: Something strange has occurred. You have a key with an expiry but no creation date. This is an invalid state.").color256(CLI_RED));
        Utc::now()
    };

    print!(" {} ", style("Expires?:").color256(CLI_BLUE));
    if let Some(expiry) = signature.key_expiration_time() {
        print!("{}", style(created + *expiry).color256(CLI_GREEN));
    } else {
        print!("{}", style("Never").color256(CLI_GREEN));
    }
    println!();

    let secret = check_crypto_algo_type(
        primary_key.primary_key.secret_params(),
        signature.key_flags(),
    )?;

    Ok((
        signature.key_flags(),
        KeyInfo {
            source: KeySourceMaterial::Imported {
                seed: secret.get_private_keymultibase().unwrap(),
            },
            secret,
            expiry: signature.key_expiration_time().map(|e| e.to_owned()),
            created,
        },
    ))
}

/// Prints the key purpose based on Key Flags
/// new_line: If true, prints a new line at the end
fn show_key_purpose(flags: KeyFlags) {
    // Key purpose from key_flags
    let mut flag = false;
    print!("{}", style("Key Purpose: ").color256(CLI_BLUE));
    if flags.sign() {
        print!("{}", style("Signing").color256(CLI_GREEN));
        flag = true;
    }

    if flags.encrypt_comms() || flags.encrypt_storage() {
        if flag {
            print!("{}", style(", ").color256(CLI_GREEN));
        }
        print!("{}", style("Encryption").color256(CLI_GREEN));
        flag = true;
    }

    if flags.authentication() {
        if flag {
            print!("{}", style(", ").color256(CLI_GREEN));
        }
        print!("{}", style("Authentication").color256(CLI_GREEN));
    }

    println!();
}

/// Ensures that only Curve25519 types are matched to the right purpose
fn check_crypto_algo_type(params: &SecretParams, flags: KeyFlags) -> Result<Secret> {
    let SecretParams::Plain(params) = params else {
        println!("{}", style("Expected to find encrypted secret parameters, instead received EncryptedSecretParams. Key was not unlocked properly").color256(CLI_RED));
        bail!("Key wasn't fully unlocked - ran into encrypted key secrets");
    };

    // Crypto algo check
    let mut secret = match params {
        PlainSecretParams::Ed25519(secret) | PlainSecretParams::Ed25519Legacy(secret) => {
            if flags.sign() || flags.authentication() {
                println!(
                    "{}",
                    style("Sucessfully retrieved Ed25519 key secret material").color256(CLI_GREEN)
                );
                Secret::generate_ed25519(None, Some(secret.as_bytes()))
            } else {
                println!(
                    "{}",
                    style("Ed25519 key cannot be used for Encryption").color256(CLI_RED)
                );
                bail!("Invalid use of Ed25519 key");
            }
        }
        PlainSecretParams::X25519(secret) => {
            if flags.encrypt_comms() || flags.encrypt_storage() {
                // Valid use of X25519
                println!(
                    "{}",
                    style("Sucessfully retrieved X25519 key secret material").color256(CLI_GREEN)
                );
                Secret::generate_x25519(None, Some(secret.as_bytes()))?
            } else {
                println!(
                    "{}",
                    style("X25519 Key can only be used for Encryption").color256(CLI_RED)
                );
                bail!("Invalid use of X25519 key");
            }
        }
        PlainSecretParams::ECDH(secret) => {
            if (flags.encrypt_comms() || flags.encrypt_storage())
                && let ecdh::SecretKey::Curve25519(secret) = secret
            {
                // Valid use of X25519
                println!(
                    "{}",
                    style("Sucessfully retrieved X25519 key secret material").color256(CLI_GREEN)
                );
                Secret::generate_x25519(None, Some(secret.as_bytes()))?
            } else if let ecdh::SecretKey::Curve25519(_) = secret {
                println!(
                    "{}",
                    style("ECDH Key must be Curve25519!").color256(CLI_RED)
                );
                bail!("Invalid use of X25519 key");
            } else {
                println!(
                    "{}",
                    style("X25519 Key can only be used for Encryption").color256(CLI_RED)
                );
                bail!("Invalid use of X25519 key");
            }
        }
        _ => {
            println!(
                "{} {}",
                style("Invalid key secret parameters: ").color256(CLI_RED),
                style(format!("{:#?}", params)).color256(CLI_ORANGE)
            );
            bail!("Invalid key secret paramters");
        }
    };

    // Set the Key ID to be the base58 encoded public key (this can be used as a basic did:key:z...
    // DID)
    secret.id = secret.get_public_keymultibase()?;
    Ok(secret)
}

/// Unlocks the master PGP Key
fn unlock_pgp_key(key: &mut pgp::packet::SecretKey, password: &str) -> Result<()> {
    println!(
        "{}{}{}",
        style("Attempting to unlock and unencrypt PGP primary key (").color256(CLI_BLUE),
        style(key.fingerprint()).color256(CLI_GREEN),
        style(")").color256(CLI_BLUE)
    );

    key.remove_password(&pgp::types::Password::from(password.as_bytes()))
        .context("Couldn't remove PGP primary key password")?;

    Ok(())
}

/// Unlocks the master PGP Key
fn unlock_pgp_sub_key(key: &mut pgp::packet::SecretSubkey, password: &str) -> Result<()> {
    println!(
        "{}{}{}",
        style("Attempting to unlock and unencrypt PGP subkey (").color256(CLI_BLUE),
        style(key.fingerprint()).color256(CLI_GREEN),
        style(")").color256(CLI_BLUE)
    );

    key.remove_password(&pgp::types::Password::from(password.as_bytes()))
        .context("Couldn't remove PGP subkey password")?;

    Ok(())
}

/// helper function to get the expiry date as a string
fn get_expiry_date(created: &DateTime<Utc>, expiry: Option<&TimeDelta>) -> StyledObject<String> {
    if let Some(expiry) = expiry {
        style((*created + *expiry).to_string()).color256(CLI_GREEN)
    } else {
        style("Never".to_string()).color256(CLI_GREEN)
    }
}

fn modify_key_expiry(key: &KeyInfo, purpose: &KeyPurpose) -> KeyInfo {
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Do you want to change the current expiry ({}) for the {} key?",
            get_expiry_date(&key.created, key.expiry.as_ref()),
            purpose,
        ))
        .default(false)
        .interact()
        .unwrap()
    {
        let re = Regex::new(
            r"(?x)
            (?P<year>\d{4})  # the year
            -
            (?P<month>\d{2}) # the month
            -
            (?P<day>\d{2})   # the day
            ",
        )
        .unwrap();

        // Change the Expiry option
        let new_expiry: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter expiry date as YYYY-MM-DD or blank to remove expiry")
            .allow_empty(true)
            .validate_with(|input: &String| {
                if input.is_empty() {
                    Ok(())
                } else if let Some(caps) = re.captures(input) {
                    let Ok(year) = str::parse::<i32>(&caps["year"]) else {
                        return Err("Year is not a valid number");
                    };
                    let Ok(month) = str::parse::<u32>(&caps["month"]) else {
                        return Err("Month is not a valid number");
                    };
                    let Ok(day) = str::parse::<u32>(&caps["day"]) else {
                        return Err("Day is not a valid number");
                    };

                    if let MappedLocalTime::Single(date) =
                        Utc.with_ymd_and_hms(year, month, day, 23, 59, 59)
                    {
                        if (date - key.created).num_days() < 1 {
                            return Err("Expiry date must be in the future");
                        } else if (date - key.created).num_days() > 65535 {
                            return Err("Expiry date must be within 65535 days (about 179 years)");
                        }
                    } else {
                        return Err("Input is not a valid date");
                    }
                    Ok(())
                } else {
                    Err("This is not a valid date")
                }
            })
            .interact()
            .unwrap();

        if new_expiry.is_empty() {
            KeyInfo {
                expiry: None,
                ..key.clone()
            }
        } else {
            let caps = re.captures(&new_expiry).unwrap();
            let date = Utc
                .with_ymd_and_hms(
                    str::parse(&caps["year"]).unwrap(),
                    str::parse(&caps["month"]).unwrap(),
                    str::parse(&caps["day"]).unwrap(),
                    23,
                    59,
                    59,
                )
                .unwrap();

            KeyInfo {
                expiry: Some(date - key.created),
                ..key.clone()
            }
        }
    } else {
        key.clone()
    }
}
