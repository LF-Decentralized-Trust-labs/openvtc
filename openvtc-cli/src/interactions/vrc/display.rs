use chrono::Local;
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use dtg_credentials::DTGCredential;
use openvtc::{
    colors::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED, CLI_WHITE},
    config::Config,
    logs::LogFamily,
    relationships::Relationship,
};
use std::{collections::HashSet, sync::Arc};

/// Remove a VRC by it's ID
pub fn remove_vrc_by_id(config: &mut Config, id: &Arc<String>) -> bool {
    if let Some(vrc) = config.vrcs.get(id) {
        vrc_show(id, vrc);

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Are you sure you want to delete VRC?")
            .interact()
            .unwrap()
        {
            config.private.vrcs_received.remove_vrc(id);
            config.private.vrcs_issued.remove_vrc(id);

            config.public.logs.insert(
                LogFamily::Relationship,
                format!("User removed VRC ID: {id}"),
            );
            true
        } else {
            println!("{}", style("Aborting VRC Removal").color256(CLI_ORANGE));
            false
        }
    } else {
        println!(
            "{}{}",
            style("ERROR: No VRC found for ID: ").color256(CLI_RED),
            style(id).color256(CLI_ORANGE)
        );
        false
    }
}

/// Shows all VRC's on screen
pub fn vrcs_show_all(config: &Config) {
    // Merge the keys from both issued and received VRC's together
    let mut keys: HashSet<Arc<String>> = config.private.vrcs_received.keys().cloned().collect();

    keys.extend(
        config
            .private
            .vrcs_issued
            .keys()
            .cloned()
            .collect::<HashSet<Arc<String>>>(),
    );

    if keys.is_empty() {
        println!(
            "{}{}{}",
            style("No Verifiable Relationship Credentials exist yet... Run ").color256(CLI_ORANGE),
            style("openvtc vrcs request").color256(CLI_WHITE),
            style(" to create a VRC request to someone").color256(CLI_ORANGE)
        );
        return;
    }

    for remote in keys {
        vrcs_show_relationship(&remote, config);
    }
}

/// Shows all VRC's for a relationship
/// remote: Must be the remote DID of the relationship (can be R-DID or P-DID)
pub fn vrcs_show_relationship(remote: &Arc<String>, config: &Config) {
    let relationship: Relationship =
        if let Some(relationship) = config.private.relationships.find_by_remote_did(remote) {
            let guard = relationship.lock().unwrap();
            guard.clone()
        } else {
            println!(
                "{}{}",
                style("ERROR: Missing relationship record for DID: ").color256(CLI_RED),
                style(remote.as_str()).color256(CLI_ORANGE)
            );
            return;
        };

    let Some(contact) = config
        .private
        .contacts
        .find_contact(&relationship.remote_p_did)
    else {
        println!(
            "{}{}",
            style("ERROR: Missing contact record for DID: ").color256(CLI_RED),
            style(&relationship.remote_p_did).color256(CLI_ORANGE)
        );
        return;
    };

    println!();
    print!(
        "{}{} {}{}",
        style("Relationship Alias: ").color256(CLI_BLUE).bold(),
        if let Some(alias) = &contact.alias {
            style(alias.as_str()).color256(CLI_GREEN)
        } else {
            style("<No Alias>").color256(CLI_ORANGE).italic()
        },
        style("Persona DID: ").color256(CLI_BLUE).bold(),
        style(&relationship.remote_p_did).color256(CLI_PURPLE)
    );
    println!();

    println!(
        "{}{}",
        style("<-- ").color256(CLI_BLUE).bold(),
        style("You have issued the following VRC's to this Relationship:")
            .color256(CLI_BLUE)
            .bold()
            .underlined()
    );
    if let Some(vrcs) = config.private.vrcs_issued.get(remote)
        && !vrcs.is_empty()
    {
        for (vrc_id, vrc) in vrcs {
            vrc_show(vrc_id, vrc);
            println!();
        }
    } else {
        println!(
            "\t{}",
            style("You haven't issued any VRC's for this relationship").color256(CLI_ORANGE)
        );
        println!();
    }

    println!(
        "{}{}",
        style("--> ").color256(CLI_BLUE).bold(),
        style("You have received the following VRC's for this Relationship:")
            .color256(CLI_BLUE)
            .bold()
            .underlined()
    );
    if let Some(vrcs) = config.private.vrcs_received.get(remote)
        && !vrcs.is_empty()
    {
        for (vrc_id, vrc) in vrcs {
            vrc_show(vrc_id, vrc);
            println!();
        }
    } else {
        println!(
            "\t{}",
            style("You haven't received any VRC's for this relationship").color256(CLI_ORANGE)
        );
        println!();
    }
}

/// Prints a vrc to the screen
pub fn vrc_show(vrc_id: &str, vrc: &DTGCredential) {
    println!(
        "\t{}{}",
        style("VRC ID: ").color256(CLI_BLUE).bold(),
        style(vrc_id).color256(CLI_PURPLE)
    );

    println!(
        "\t  {}{} {}{}",
        style("Valid From: ").color256(CLI_BLUE).bold(),
        style(
            &vrc.valid_from()
                .with_timezone(&Local)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )
        .color256(CLI_WHITE),
        style("Valid Until?: ").color256(CLI_BLUE).bold(),
        if let Some(valid_until) = vrc.valid_until() {
            style(
                valid_until
                    .with_timezone(&Local)
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
            .color256(CLI_WHITE)
        } else {
            style("Forever".to_string()).color256(CLI_ORANGE)
        },
    );
}

/// Prints a VRC JSON to screen
pub fn show_vrc_by_id(config: &Config, id: &str) {
    if let Some(vrc) = config.vrcs.get(&Arc::new(id.to_string())) {
        println!(
            "{}{}\n{}",
            style("VRC ID: ").color256(CLI_BLUE).bold(),
            style(id).color256(CLI_PURPLE),
            style(serde_json::to_string_pretty(&vrc).unwrap()).color256(CLI_WHITE)
        )
    } else {
        println!(
            "{}{}",
            style("ERROR: No VRC found with ID: ").color256(CLI_RED),
            style(id).color256(CLI_ORANGE)
        )
    }
}
