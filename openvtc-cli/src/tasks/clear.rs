/*!
*   Clears Tasks locally and remotely
*/

use crate::{CLI_BLUE, CLI_GREEN, tasks::Tasks};
use affinidi_tdk::{
    TDK,
    messaging::{
        ATM,
        messages::{FetchDeletePolicy, fetch::FetchOptions},
    },
};
use anyhow::Result;
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};
use openvtc::config::Config;

pub trait TasksClear {
    async fn clear_all(tdk: &TDK, config: &mut Config, force: bool, remote: bool) -> Result<bool>;
}

impl TasksClear for Tasks {
    /// Clears all tasks
    /// force: Whether to ask for confirmation (no if true)
    /// remote: Deletes all messages on the DIDComm mediator if true
    async fn clear_all(tdk: &TDK, config: &mut Config, force: bool, remote: bool) -> Result<bool> {
        let atm = tdk.atm.clone().unwrap();
        let mut change_flag = false;

        if !force
            && !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(
                    "Are you sure you want to clear all tasks? This action cannot be undone.",
                )
                .default(false)
                .interact()?
        {
            println!("{}", style("Aborting clear operation.").color256(CLI_GREEN));
            return Ok(false);
        }

        // Remove remote queued tasks
        if remote {
            let mut task_count: usize = 0;
            loop {
                let c = delete_remote(&atm, config).await?;
                task_count += c;
                if c < 100 {
                    break;
                }
            }
            if task_count > 0 {
                change_flag = true;
            }

            println!(
                "{}{}{}",
                style("Successfully removed ").color256(CLI_BLUE),
                style(task_count).color256(CLI_GREEN),
                style(" tasks from remote server").color256(CLI_BLUE)
            );
        }

        // Remove local tasks
        let local_task_count = config.private.tasks.tasks.len();
        if config.private.tasks.clear() {
            change_flag = true;
        }

        println!(
            "{}{}{}",
            style("Removed ").color256(CLI_BLUE),
            style(local_task_count).color256(CLI_GREEN),
            style(" tasks from local storage").color256(CLI_BLUE)
        );

        Ok(change_flag)
    }
}

async fn delete_remote(atm: &ATM, config: &Config) -> Result<usize> {
    let msgs = atm
        .fetch_messages(
            &config.persona_did.profile,
            &FetchOptions {
                limit: 100,
                start_id: None,
                delete_policy: FetchDeletePolicy::Optimistic,
            },
        )
        .await?;

    Ok(msgs.success.len())
}
