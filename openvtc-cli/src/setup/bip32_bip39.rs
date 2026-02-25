/*! BIP32 (derived keys) and BIP39 (mnemonic recovery phrases)
*  implementations live here
*/

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_RED};
use anyhow::{Context, Result, bail};
use bip39::Mnemonic;
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use rand::RngCore;
use zeroize::Zeroize;

// ****************************************************************************
// BIP39 Mnemonic Handling
// ****************************************************************************

/// Prompts the user to enter their recovery phrase to recover entropy seed
pub fn mnemonic_from_recovery_phrase() -> Result<Mnemonic> {
    println!("{}", style("You can recover your secrets by entering your 24 word recovery phrase separated by whitespace below").color256(CLI_BLUE));

    fn inner() -> Result<Mnemonic> {
        let input: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter your 24 word recovery phrase")
            .report(false)
            .interact_text()
            .context("Couldn't read recovery phrase from user input")?;

        // Check that the phrase looks valid
        let words: Vec<&str> = input.split_whitespace().collect();
        if words.len() != 24 {
            bail!("Recovery phrase must be 24 words long, got {}", words.len());
        }

        Mnemonic::parse_normalized(&input).context("Couldn't derive BIP39 mnemonic from words")
    }

    loop {
        match inner() {
            Ok(mnemonic) => {
                println!("{}", style("Recovery phrase accepted!").color256(CLI_GREEN));
                return Ok(mnemonic);
            }
            Err(e) => {
                println!("{}", style(e).color256(CLI_RED));

                if !Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Try again?")
                    .default(true)
                    .interact()
                    .unwrap()
                {
                    bail!("BIP39 Recovery failed")
                }
            }
        }
    }
}

/// Generates a new BIP39 Mnemonic that is used as a seed and recovery phrase
pub fn generate_bip39_mnemonic() -> Mnemonic {
    // Create 256 bits of entropy
    let mut entropy = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy);

    match Mnemonic::from_entropy(&entropy) {
        Ok(mnemonic) => {
            entropy.zeroize(); // Clear entropy from memory

            println!(
                "\n{} {}",
                style("BIP39 Recovery Phrase").color256(CLI_BLUE),
                style("(Please store in a safe space):")
                    .color256(CLI_RED)
                    .blink()
            );
            println!(
                "{}",
                style(mnemonic.words().collect::<Vec<&str>>().join(" ")).color256(CLI_ORANGE)
            );
            println!();
            mnemonic
        }
        Err(e) => {
            panic!("Error creating BIP39 mnemonic from entropy: {e}");
        }
    }
}
