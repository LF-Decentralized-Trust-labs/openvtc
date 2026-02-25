/*! Main entry point for task management
*   A [Task] is something that requires action on behalf of the user
*/

use crate::{
    CLI_BLUE, CLI_ORANGE, CLI_PURPLE, CLI_RED,
    tasks::{clear::TasksClear, fetch::fetch_tasks, interact::TasksInteraction},
};
use affinidi_tdk::{TDK, messaging::profiles::ATMProfile};
use anyhow::{Result, bail};
use clap::ArgMatches;
use console::{Term, style};
use openvtc::{
    config::Config,
    tasks::{Task, TaskType, Tasks},
};
use std::sync::Arc;

pub mod clear;
pub mod fetch;
pub mod interact;

// ****************************************************************************
// Tasks Struct
// ****************************************************************************

pub trait TasksExtension {
    fn print_tasks(&self);
}

impl TasksExtension for Tasks {
    /// Prints known tasks to the console
    fn print_tasks(&self) {
        if self.tasks.is_empty() {
            println!(
                "{}",
                style("There are no tasks currently").color256(CLI_ORANGE)
            );
        } else {
            for (task_id, task) in &self.tasks {
                let task = task.lock().unwrap();
                print!(
                    "{}{} {}{} {}{}",
                    style("Id: ").color256(CLI_BLUE),
                    style(&task_id).color256(CLI_PURPLE),
                    style("Type: ").color256(CLI_BLUE),
                    style(&task.type_).color256(CLI_PURPLE),
                    style("Created: ").color256(CLI_BLUE),
                    style(&task.created).color256(CLI_PURPLE),
                );
                match &task.type_ {
                    TaskType::TrustPing { relationship, .. } => {
                        let lock = relationship.lock().unwrap();
                        print!(
                            " {} {}",
                            style("Remote P-DID:").color256(CLI_BLUE),
                            style(&lock.remote_p_did).color256(CLI_PURPLE)
                        );
                    }
                    TaskType::VRCRequestOutbound { relationship } => {
                        let lock = relationship.lock().unwrap();
                        print!(
                            " {} {}",
                            style("Remote P-DID:").color256(CLI_BLUE),
                            style(&lock.remote_p_did).color256(CLI_PURPLE)
                        );
                    }
                    _ => {}
                }
                println!();
            }
        }
    }
}

// ****************************************************************************
// Primary entry point for Tasks from the CLI
// ****************************************************************************

/// Primary entry point for the Tasks module from the CLI
pub async fn tasks_entry(
    tdk: TDK,
    config: &mut Config,
    profile: &str,
    args: &ArgMatches,
    term: &Term,
) -> Result<()> {
    match args.subcommand() {
        Some(("list", _)) => {
            config.private.tasks.print_tasks();
        }
        Some(("remove", sub_args)) => {
            let id = if let Some(id) = sub_args.get_one::<String>("id") {
                id.to_string()
            } else {
                println!(
                    "{}",
                    style("ERROR: A task ID must be specified!").color256(CLI_RED)
                );
                bail!("Invalid CLI options");
            };

            if config.private.tasks.remove(&Arc::new(id)) {
                config.save(
                    profile,
                    #[cfg(feature = "openpgp-card")]
                    &|| {
                        eprintln!("Touch confirmation needed for decryption");
                    },
                )?;
            }
        }
        Some(("fetch", _)) => {
            let mut change_flag = false;
            if fetch_tasks(&tdk, config, term, &config.persona_did.profile.clone()).await? > 0 {
                change_flag = true;
            }
            let profiles: Vec<Arc<ATMProfile>> = config.atm_profiles.values().cloned().collect();
            for profile in profiles {
                if fetch_tasks(&tdk, config, term, &profile).await? > 0 {
                    change_flag = true;
                }
            }
            if change_flag {
                config.save(
                    profile,
                    #[cfg(feature = "openpgp-card")]
                    &|| {
                        eprintln!("Touch confirmation needed for decryption");
                    },
                )?;
            }
        }
        Some(("interact", sub_args)) => {
            if let Some(task_id) = sub_args.get_one::<String>("id").map(|id| id.to_string()) {
                let task = if let Some(task) =
                    config.private.tasks.get_by_id(&Arc::new(task_id.clone()))
                {
                    task.clone()
                } else {
                    println!(
                        "{}{}",
                        style("ERROR: No task with ID: ").color256(CLI_RED),
                        style(task_id).color256(CLI_ORANGE)
                    );
                    bail!("Unknown Task ID");
                };

                if Tasks::interact_task(&task, &tdk, config).await? {
                    config.save(
                        profile,
                        #[cfg(feature = "openpgp-card")]
                        &|| {
                            eprintln!("Touch confirmation needed for decryption");
                        },
                    )?;
                    return Ok(());
                }
            }

            if Tasks::interact(&tdk, config, term).await? {
                config.save(
                    profile,
                    #[cfg(feature = "openpgp-card")]
                    &|| {
                        eprintln!("Touch confirmation needed for decryption");
                    },
                )?;
            }
        }
        Some(("clear", sub_args)) => {
            // Removes all tasks from the remote server as well as locally
            let force = sub_args.get_flag("force");
            let remote = sub_args.get_flag("remote");

            if Tasks::clear_all(&tdk, config, force, remote).await? {
                config.save(
                    profile,
                    #[cfg(feature = "openpgp-card")]
                    &|| {
                        eprintln!("Touch confirmation needed for decryption");
                    },
                )?;
                return Ok(());
            }
        }
        _ => {
            println!(
                "{} {}",
                style("ERROR:").color256(CLI_RED),
                style("No valid tasks subcommand was used. Use --help for more information.")
                    .color256(CLI_ORANGE)
            );
            bail!("Invalid CLI Options");
        }
    }

    Ok(())
}
