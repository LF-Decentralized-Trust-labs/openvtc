mod display;
mod issued;
mod request;

pub use display::*;
pub use issued::*;
pub use request::*;

use crate::config::save_config;
use anyhow::{Result, bail};
use clap::ArgMatches;
use console::style;
use dialoguer::{Input, Select, theme::ColorfulTheme};
use openvtc::{
    colors::{CLI_BLUE, CLI_ORANGE, CLI_PURPLE, CLI_RED, CLI_WHITE},
    config::Config,
    relationships::Relationship,
    vrc::VrcRequest,
};
use std::sync::{Arc, Mutex};

use affinidi_tdk::TDK;

pub trait Print {
    fn print(&self);
}

impl Print for VrcRequest {
    fn print(&self) {
        println!();
        println!("{}", style("VRC request details: ").color256(CLI_BLUE));

        println!();
        print!("{}", style("Request reason: ").color256(CLI_BLUE));
        if let Some(reason) = &self.reason {
            println!("{}", style(reason).color256(CLI_PURPLE));
        } else {
            println!("{}", style("NO REASON PROVIDED").color256(CLI_ORANGE));
        }

        println!();
    }
}

/// Primary entry point for VRCs interactions
pub async fn vrcs_entry(
    tdk: TDK,
    config: &mut Config,
    profile: &str,
    args: &ArgMatches,
) -> Result<()> {
    match args.subcommand() {
        Some(("request", _)) => {
            if vrcs_interactive_request(&tdk, config).await? {
                save_config(config, profile)?;
            }
        }
        Some(("list", sub_args)) => {
            if let Some(remote) = sub_args.get_one::<String>("remote") {
                if let Some(contact) = config.private.contacts.find_contact(&Arc::new(remote)) {
                    vrcs_show_relationship(&contact.did, config);
                } else {
                    println!(
                        "{}{}",
                        style("WARN: Couldn't find any matching contact/relationship for: ")
                            .color256(CLI_ORANGE),
                        style(remote).color256(CLI_WHITE)
                    );
                }
            } else {
                vrcs_show_all(config);
            }
        }
        Some(("show", sub_args)) => {
            if let Some(id) = sub_args.get_one::<String>("id") {
                show_vrc_by_id(config, id);
            } else {
                println!(
                    "{}",
                    style("WARN: You must specify a VRC ID!").color256(CLI_ORANGE)
                );
            }
        }
        Some(("remove", sub_args)) => {
            if let Some(id) = sub_args.get_one::<String>("id") {
                remove_vrc_by_id(config, &Arc::new(id.to_string()));

                save_config(config, profile)?;
            } else {
                println!(
                    "{}",
                    style("WARN: You must specify a VRC ID!").color256(CLI_ORANGE)
                );
            }
        }
        _ => {
            println!(
                "{} {}",
                style("ERROR:").color256(CLI_RED),
                style("No valid vrcs subcommand was used. Use --help for more information.")
                    .color256(CLI_ORANGE)
            );
            bail!("Invalid CLI Options");
        }
    }

    Ok(())
}

fn select_relationship(config: &Config) -> Option<Arc<Mutex<Relationship>>> {
    let mut items: Vec<String> = Vec::new();
    let relationships = config.private.relationships.get_established_relationships();
    if relationships.is_empty() {
        println!("{}", style("No relationships found.").color256(CLI_ORANGE));
        println!();
        println!(
            "{} \n{}",
            style("To create a relationship, run:").color256(CLI_BLUE),
            style("openvtc relationships request --respondent <did> --alias <respondent-alias>")
                .color256(CLI_BLUE)
        );
        return None;
    }

    for r in &relationships {
        let Ok(lock) = r.lock() else {
            continue;
        };
        let alias = if let Some(contact) = config.private.contacts.contacts.get(&lock.remote_p_did)
            && let Some(alias) = &contact.alias
        {
            alias.to_string()
        } else {
            "N/A".to_string()
        };

        items.push(format!("{} :: {}", alias, lock.remote_p_did));
    }

    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select from the list (press ESC or q to quit): ")
        .items(items)
        .interact_opt()
        .ok()
        .flatten();

    if let Some(selected) = selected {
        Some(relationships[selected].clone())
    } else {
        println!(
            "{}",
            style("No relationship selected.").color256(CLI_ORANGE)
        );
        None
    }
}

fn generate_vrc_request_body() -> Result<VrcRequest> {
    let reason: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter a reason for the VRC request (optional, press Enter to skip)")
        .allow_empty(true)
        .interact_text()?;

    let reason = if reason.trim().is_empty() {
        None
    } else {
        Some(reason.trim().to_string())
    };

    Ok(VrcRequest { reason })
}
