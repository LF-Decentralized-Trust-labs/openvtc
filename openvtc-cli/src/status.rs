/* Prints diagnostic status for the tool
*
*/

use crate::{
    cli,
    config::{ConfigExtension, PublicConfigExtension},
    messaging::ping_mediator,
};
use affinidi_tdk::TDK;
use anyhow::Result;
use console::{Term, style};
use dialoguer::{Password, theme::ColorfulTheme};
#[cfg(feature = "openpgp-card")]
use openvtc::config::TokenInteractions;
use openvtc::{
    colors::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED},
    config::{Config, ConfigProtectionType, UnlockCode, public_config::PublicConfig},
};
use secrecy::SecretString;
use std::time::SystemTime;

/// Prints diagnostic status to STDOUT
pub async fn print_status(term: &Term, tdk: &mut TDK, profile: &str) {
    println!(
        "{}",
        style("First Person Protocol (OpenVTC) tool").color256(CLI_BLUE)
    );
    println!(
        "{}",
        style("==============================================").color256(CLI_BLUE)
    );
    println!(
        "{}",
        style("  BLUE : Informational text").color256(CLI_BLUE),
    );
    println!("{}", style(" GREEN : KNOWN GOOD value").color256(CLI_GREEN));
    println!(
        "{}",
        style("PURPLE : Unconfirmed OK value").color256(CLI_PURPLE),
    );
    println!(
        "{}",
        style("ORANGE : Different to expected value (may not be an issue)").color256(CLI_ORANGE),
    );
    println!(
        "{}",
        style("   RED : Incorrect value (is an ISSUE!)").color256(CLI_RED),
    );
    println!();
    println!(
        "{} {}",
        style("openvtc version:").color256(CLI_BLUE),
        style(env!("CARGO_PKG_VERSION")).bold().color256(CLI_GREEN)
    );

    feature_flags();

    // Show any openpgp-cards and corresponding status
    if let Err(error) = openpgp_cards_status() {
        println!(
            "{} {}",
            style("An error occurred in handling openpgp-cards:").color256(CLI_RED),
            style(error.to_string()).color256(CLI_ORANGE)
        );
    }

    // Load public config first to run some pre-checks
    let pub_config = match PublicConfig::load(profile) {
        Ok(pc) => pc,
        Err(e) => {
            println!(
                "{} {}",
                style("Couldn't load public configuration information. Reason:").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            return;
        }
    };

    pub_config.status();

    // Check Persona DID Resolution status
    println!();
    print!(
        "{}{}{}",
        style("Resolving Persona DID (").color256(CLI_BLUE),
        style(&pub_config.persona_did).color256(CLI_PURPLE),
        style(")...").color256(CLI_BLUE)
    );
    let _ = term.hide_cursor();
    let _ = term.flush();

    match tdk.did_resolver().resolve(&pub_config.persona_did).await {
        Ok(result) => {
            let _ = term.show_cursor();
            println!(
                " {}",
                style("✅ Success in resolving DID").color256(CLI_GREEN)
            );

            // Check that DID ID's match as expected
            if result.doc.id.as_str() == pub_config.persona_did.as_str() {
                println!(
                    "{} {}",
                    style("Resolved DID matches ID in config?").color256(CLI_BLUE),
                    style("Matches!").color256(CLI_GREEN)
                );
            } else {
                println!(
                    "{} {}",
                    style("ERROR: Resolved DID ID does not match!").color256(CLI_RED),
                    style(format!("Expected ({})", &pub_config.persona_did)).color256(CLI_ORANGE)
                );
                println!(
                    "{}",
                    style(format!("Instead resolved ({})", result.doc.id.as_str()))
                        .color256(CLI_ORANGE)
                );
                return;
            }
        }
        Err(e) => {
            println!(
                "{} {}",
                style("ERROR: Couldn't resolve DID! Reason:").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            return;
        }
    }

    #[cfg(feature = "openpgp-card")]
    let a = {
        struct A;
        impl TokenInteractions for A {
            fn touch_notify(&self) {
                eprintln!("Touch confirmation needed for decryption");
            }
            fn touch_completed(&self) {
                eprintln!("Touch ompleted");
            }
        }
        A
    };

    let public_config = match Config::load_step1(profile) {
        Ok(pc) => pc,
        Err(e) => {
            println!(
                "{}{}",
                style("ERROR: Couldn't complete step1 of loading config. Reason: ")
                    .color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            return;
        }
    };

    let (user_pin, unlock_passphrase) = match &public_config.protection {
        ConfigProtectionType::Token { .. } => {
            let user_pin = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Please enter Token User PIN <blank = default>")
                .allow_empty_password(true)
                .interact()
                .unwrap();
            let user_pin = if user_pin.is_empty() {
                SecretString::new("123456".to_string())
            } else {
                SecretString::new(user_pin)
            };

            (user_pin, None)
        }
        ConfigProtectionType::Encrypted => {
            let passphrase =
                if let Some(passphrase) = cli().get_matches().get_one::<String>("unlock-code") {
                    passphrase.to_string()
                } else {
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Please enter unlock passphrase")
                        .allow_empty_password(false)
                        .interact()
                        .unwrap()
                };
            (
                SecretString::new(String::new()),
                Some(UnlockCode::from_string(&passphrase)),
            )
        }
        ConfigProtectionType::Plaintext => (SecretString::new(String::new()), None),
    };

    let config = match Config::load_step2(
        tdk,
        profile,
        public_config,
        unlock_passphrase.as_ref(),
        #[cfg(feature = "openpgp-card")]
        &user_pin,
        #[cfg(feature = "openpgp-card")]
        &a,
    )
    .await
    {
        Ok(cfg) => {
            println!(
                "{} {}",
                style("openvtc secured configuration:").color256(CLI_BLUE),
                style("✅ successfully loaded").color256(CLI_GREEN)
            );
            cfg
        }
        Err(e) => {
            println!(
                "{}{}",
                style("ERROR: Couldn't load configuration: ").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            return;
        }
    };

    config.status();

    // Are the DIDComm mediators working?
    println!();
    println!("{}", style("DIDComm Messaging").bold().color256(CLI_BLUE));
    println!("{}", style("=================").bold().color256(CLI_BLUE));
    println!(
        "{} {}",
        style("Public Mediator DID:").color256(CLI_BLUE),
        style(&config.public.mediator_did).color256(CLI_PURPLE)
    );

    print!(
        "{}",
        style("Sending trust-ping to public-mediator...").color256(CLI_BLUE)
    );
    let _ = term.hide_cursor();
    let _ = term.flush();
    let start = SystemTime::now();
    match ping_mediator(tdk, &config).await {
        Ok(_) => {
            let end = SystemTime::now();
            let _ = term.show_cursor();
            println!(
                " {}{}{}",
                style("✅ Successfull ping/pong. RTT: ").color256(CLI_GREEN),
                style(end.duration_since(start).unwrap().as_millis()).color256(CLI_GREEN),
                style("ms").color256(CLI_GREEN)
            );
        }
        Err(e) => {
            let _ = term.show_cursor();
            println!(
                "{} {}",
                style("ERROR: Couldn't ping public-mediator. Reason:").color256(CLI_RED),
                style(e).color256(CLI_ORANGE)
            );
            return;
        }
    }

    println!();
    println!(
        "{}",
        style("👍 Everything looks to be ok!").color256(CLI_GREEN)
    )
}

// Rust Feature Flags enabled for this build
fn feature_flags() {
    print!("{} ", style("openvtc enabled features:").color256(CLI_BLUE),);
    let mut prev_flag = false; // set to true if a feature has been enabled

    #[cfg(not(feature = "default"))]
    {
        print!("{}", style("no-default").color256(CLI_RED));
        prev_flag = true;
    }

    #[cfg(feature = "default")]
    {
        if prev_flag {
            print!("{}", style(", ").bold().color256(CLI_GREEN))
        }
        print!("{}", style("default").bold().color256(CLI_GREEN));
        prev_flag = true;
    }

    #[cfg(feature = "openpgp-card")]
    {
        if prev_flag {
            print!("{}", style(", ").bold().color256(CLI_GREEN))
        }
        print!("{}", style("openpgp-card").bold().color256(CLI_GREEN));
    }

    println!();
}

fn openpgp_cards_status() -> Result<()> {
    println!();
    print!("{} ", style("OpenPGP Card support:").color256(CLI_BLUE));

    #[cfg(not(feature = "openpgp-card"))]
    println!("{}", style("DISABLED").color256(CLI_ORANGE).bold());

    #[cfg(feature = "openpgp-card")]
    {
        use openvtc::openpgp_card::get_cards;

        use crate::openpgp_card::print_cards;

        println!("{} ", style("Enabled").color256(CLI_GREEN).bold());

        let mut cards = get_cards()?;
        print_cards(&mut cards)?;
    }

    Ok(())
}
