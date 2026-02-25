/*! Command Line Interface configuration
*/

use clap::{Arg, Command};
use dialoguer::{Password, theme::ColorfulTheme};
use secrecy::SecretString;

pub fn cli() -> Command {
    // Full CLI Set
    Command::new("openvtc")
        .about("First Person Protocol")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .args([
            Arg::new("unlock-code")
                .short('u')
                .long("unlock-code")
                .help("If using unlock codes, can specify it here"),
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Config profile to use")
                .default_value("default"),
        ])
        .subcommand(Command::new("setup").about("Initial configuration of the openvtc tool"))
}

pub fn get_user_pin() -> SecretString {
    let user_pin = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter Token User PIN")
        .allow_empty_password(false)
        .interact()
        .unwrap();
    if user_pin.is_empty() {
        SecretString::new("123456".to_string())
    } else {
        SecretString::new(user_pin)
    }
}
