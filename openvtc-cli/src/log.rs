/*!
*  Manages a log of messages that can be helpfuil to see what has happened in the past.
*/

use crate::{CLI_BLUE, CLI_GREEN, CLI_ORANGE, CLI_PURPLE};
use console::style;
use openvtc::logs::Logs;

pub trait LogsExtension {
    fn show_all(&self);
}

impl LogsExtension for Logs {
    /// Shows all log files to STDOUT
    fn show_all(&self) {
        if self.messages.is_empty() {
            println!("{}", style("There are no log entries").color256(CLI_ORANGE));
        } else {
            for log in &self.messages {
                println!(
                    "{} {} {} {}",
                    style(log.created).color256(CLI_GREEN),
                    style(&log.type_).color256(CLI_PURPLE),
                    style("::").color256(CLI_BLUE),
                    style(&log.message).color256(CLI_GREEN)
                );
            }
        }
    }
}
