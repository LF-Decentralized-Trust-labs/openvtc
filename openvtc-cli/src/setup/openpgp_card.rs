/*!
*   Stores the Persona DID Secrets on an OpenPGP compatible card (E.g. Nitrokey)
*/

use crate::{
    openpgp_card::{
        factory_reset, print_cards, set_cardholder_name, set_signing_touch_policy,
        write::write_keys_to_card,
    },
    setup::PersonaDIDKeys,
    CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED,
};
use anyhow::{bail, Result};
use console::{style, Term};
use crossterm::{
    event::{self, Event},
    terminal,
};
use dialoguer::{theme::ColorfulTheme, Confirm, Select};
use openvtc::openpgp_card::get_cards;
use secrecy::SecretString;

/// Handles storing secrets on an OpenPGP compatible card
/// Returns:
/// None: No Hardware token being used
/// Some(String): The card identifier of the card used
pub fn setup_hardware_token(
    term: &Term,
    admin_pin: &SecretString,
    keys: &PersonaDIDKeys,
) -> Result<Option<String>> {
    println!();

    println!(
        "{}\n{}",
        style("If you intend to use a hardware token, please ensure it is plugged in now.")
            .color256(CLI_BLUE),
        style("Press any key to continue...")
            .color256(CLI_PURPLE)
            .blink()
    );
    terminal::enable_raw_mode()?;
    loop {
        // Read the next event
        match event::read()? {
            // If it's a key event and a key press
            Event::Key(key_event) if key_event.kind == event::KeyEventKind::Press => {
                break;
            }
            _ => {} // Ignore other events (mouse, resize, etc.)
        }
    }
    // Disable raw mode when done
    terminal::disable_raw_mode()?;

    println!(
        "\n{}\n",
        style("Searching for OpenPGP-compatible hardware tokens...").color256(CLI_BLUE)
    );

    // Detect cards and show
    let mut cards = get_cards()?;
    if cards.is_empty() {
        println!(
            "{}\n",
            style("No compatible hardware tokens were found.").color256(CLI_ORANGE)
        );
        return Ok(None);
    } else {
        print_cards(&mut cards)?;
    }

    let mut s_card: Vec<String> = cards
        .iter_mut()
        .map(|c| {
            let mut lock = c.try_lock().unwrap();
            lock.transaction()
                .unwrap()
                .application_identifier()
                .unwrap()
                .ident()
        })
        .collect();

    s_card.push("Do not use a hardware token.".to_string());

    println!();
    let selected_option = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the card you would like to use to store your secrets:")
        .default(0)
        .items(&s_card)
        .interact()
        .unwrap();

    if selected_option == s_card.len() - 1 {
        println!(
            "{}",
            style("Skipping hardware token setup...").color256(CLI_ORANGE)
        );
        return Ok(None);
    }

    let Some(selected_card) = cards.get_mut(selected_option) else {
        println!(
            "\n{}{}{}",
            style("Unable to find the card (").color256(CLI_RED),
            style(s_card.get(selected_option).unwrap()).color256(CLI_ORANGE),
            style(").").color256(CLI_RED)
        );
        bail!("\nUnable to select the card for storing...");
    };

    // Ask to factory reset card?
    println!(
        "\n{}",
        style(
            "It is recommended to factory reset your hardware token to ensure a fresh and known starting point."
        ).color256(CLI_BLUE)
    );
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "\nWould you like to factory reset the card before storing the secrets? {}",
            style("(This will delete all existing keys on the card)").color256(CLI_ORANGE),
        ))
        .default(false)
        .interact()?
    {
        factory_reset(term, selected_card)?;
    }

    // Open the card in admin mode

    // Attempt to write the keys to the card
    write_keys_to_card(term, selected_card, keys, admin_pin)?;

    // Set Touch on for the Signing Key
    println!("\n{}\n", style("Best practice is to force an interaction with the hardware token for critical operations, such as signing data.").color256(CLI_BLUE));
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Would you like to set the Signing key to require touch? {}",
            style(
                "(This will require you to touch the hardware token every time you sign something)"
            )
            .color256(CLI_GREEN),
        ))
        .default(true)
        .interact()?
    {
        set_signing_touch_policy(term, selected_card, admin_pin)?;
    } else {
        println!(
            "{}",
            style("The Signing key will NOT require touch.").color256(CLI_ORANGE)
        );
    }

    // Set cardholder name?
    println!(
        "{}{}\n{}\n",
        style("You can set a cardholder name (max 39 characters).\nRecommended Format: ")
            .color256(CLI_BLUE),
        style("LAST_NAME<<FIRST_NAME<OTHER<OTHER").color256(CLI_PURPLE),
        style(
            "NOTE: You are free to enter any name in the cardholder name. No encoding is applied."
        )
        .color256(CLI_BLUE)
    );

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Would you like to set the Cardholder Name?")
        .default(true)
        .interact()?
    {
        let cardholder_name: String = dialoguer::Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Cardholder Name: ")
            .validate_with(|input: &String| {
                if input.len() > 39 {
                    Err("Cardholder name must be 39 characters or less.\n")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;
        set_cardholder_name(term, selected_card, admin_pin, &cardholder_name)?;
    }

    // Return the card identifier
    Ok(s_card.get(selected_option).map(|s| s.to_string()))
}
