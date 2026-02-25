/*!
*  Managing known contacts is useful and easy to establish relationships with others
*/

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE, CLI_RED};
use affinidi_tdk::TDK;
use anyhow::{Result, bail};
use clap::{ArgMatches, Id};
use console::style;
use openvtc::{
    config::protected_config::Contacts,
    logs::Logs,
    relationships::{RelationshipState, Relationships},
};

pub trait ContactsExtension {
    async fn contacts_entry(
        &mut self,
        tdk: TDK,
        args: &ArgMatches,
        relationships: &Relationships,
        logs: &mut Logs,
    ) -> Result<bool>;

    fn print_list(&self, relationships: &Relationships);
}

impl ContactsExtension for Contacts {
    /// Primary entry point for all Contact Management related functionality
    /// Returns true if config changed and needs to be saved
    async fn contacts_entry(
        &mut self,
        tdk: TDK,
        args: &ArgMatches,
        relationships: &Relationships,
        logs: &mut Logs,
    ) -> Result<bool> {
        Ok(match args.subcommand() {
            Some(("add", sub_args)) => {
                let did = if let Some(did) = sub_args.get_one::<String>("did") {
                    did.to_string()
                } else {
                    println!(
                        "{}",
                        style("ERROR: You must specify a DID to add!").color256(CLI_RED)
                    );
                    bail!("Contact DID is required");
                };
                let alias = sub_args.get_one::<String>("alias");
                let skip = sub_args.get_flag("skip");

                self.add_contact(&tdk, &did, alias.map(|s| s.to_string()), skip, logs)
                    .await?;

                println!(
                    "{}",
                    style("Successfully added new contact").color256(CLI_GREEN)
                );
                if let Some(alias) = alias {
                    print!(
                        "  {}{}{}",
                        style("alias (").color256(CLI_BLUE),
                        style(alias).color256(CLI_PURPLE),
                        style(")").color256(CLI_BLUE),
                    );
                } else {
                    print!(
                        "  {}{}{}",
                        style("alias (").color256(CLI_BLUE),
                        style("NONE").color256(CLI_ORANGE),
                        style(")").color256(CLI_BLUE),
                    );
                }
                println!(
                    " {}{}{}",
                    style("contact DID (").color256(CLI_BLUE),
                    style(did).color256(CLI_PURPLE),
                    style(")").color256(CLI_BLUE),
                );
                true
            }
            Some(("remove", sub_args)) => {
                let name = sub_args
                    .get_one::<Id>("remove-by")
                    .expect("No valid contact name to remove")
                    .as_str();
                let id = sub_args.get_one::<String>(name).unwrap();

                let changed = self.remove_contact(logs, id);

                if let Some(changed) = changed {
                    println!(
                        "{}{}{}",
                        style("Successfully removed contact (").color256(CLI_GREEN),
                        style(&changed.did).color256(CLI_PURPLE),
                        style(")").color256(CLI_GREEN)
                    );
                    true
                } else {
                    println!(
                        "{}{}{}",
                        style("No contact found that matched (").color256(CLI_ORANGE),
                        style(id).color256(CLI_PURPLE),
                        style(")").color256(CLI_ORANGE)
                    );
                    false
                }
            }
            Some(("list", _)) => {
                self.print_list(relationships);
                false
            }
            _ => {
                println!(
                    "{} {}",
                    style("ERROR:").color256(CLI_RED),
                    style(
                        "No valid contacts subcommand was used. Use --help for more information."
                    )
                    .color256(CLI_ORANGE)
                );
                false
            }
        })
    }

    // Dumps contct information to the console
    fn print_list(&self, relationships: &Relationships) {
        if self.is_empty() {
            println!(
                "{}",
                style("There are no known contacts").color256(CLI_ORANGE)
            );
            return;
        }

        for contact in self.contacts.values() {
            if let Some(alias) = &contact.alias {
                print!(
                    "  {}{}{}",
                    style("alias (").color256(CLI_BLUE),
                    style(alias).color256(CLI_PURPLE),
                    style(")").color256(CLI_BLUE),
                );
            } else {
                print!(
                    "  {}{}{}",
                    style("alias (").color256(CLI_BLUE),
                    style("NONE").color256(CLI_ORANGE),
                    style(")").color256(CLI_BLUE),
                );
            }

            let relationship_status = if let Some(relationship) = relationships.get(&contact.did) {
                style(relationship.lock().unwrap().state.clone()).color256(CLI_GREEN)
            } else {
                style(RelationshipState::None).color256(CLI_ORANGE)
            };

            println!(
                " {}{}{} {}{}",
                style("contact DID (").color256(CLI_BLUE),
                style(&contact.did).color256(CLI_PURPLE),
                style(")").color256(CLI_BLUE),
                style("Relationship status: ").color256(CLI_BLUE),
                relationship_status
            );
        }
    }
}
