/*! Command Line Interface configuration
*/

use clap::{Arg, ArgAction, Command};

pub fn cli() -> Command {
    // To help with readability, some sub-commands get pulled out separately

    // Handles exporting various settings and information
    let export_subcommand = Command::new("export")
        .about("Export settings and other information")
        .subcommands([
    Command::new("pgp-keys").args([
                Arg::new("passphrase")
                    .short('p')
                    .long("passphrase")
                    .help("Passphrase to lock the exported PGP Secrets with"),
                Arg::new("user-id")
                    .short('u')
                    .long("user-id")
                    .help("PGP User Id 'name <email_address>' format")
                    .value_name("first_name last_name <email@domain>")
            ])
            .about("Exports first set of keys used in your Persona DID for Signing, Authentication and Decryption"),
            Command::new("settings").args([
                Arg::new("passphrase")
                    .short('p')
                    .long("passphrase")
                    .help("Passphrase to lock the exported settings with"),
                Arg::new("file").short('f').long("file").help("File to save settings to").default_value("export.openvtc"),
            ]).about("Exports settings which can be imported into another openvtc installation")
        ])
        .arg_required_else_help(true);

    // Contact management
    let contacts_subcommand = Command::new("contacts")
        .about("Manage known contacts")
        .subcommand(Command::new("list").about("Lists all known contacts"))
        .subcommand(
            Command::new("add")
                .args([
                    Arg::new("did")
                        .short('d')
                        .long("did")
                        .help("DID of the contact to add")
                        .required(true),
                    Arg::new("alias")
                        .short('a')
                        .long("alias")
                        .help("Optional alias for the contact"),
                    Arg::new("skip")
                        .short('s')
                        .long("skip")
                        .default_value("true")
                        .action(ArgAction::SetFalse)
                        .help("Skip DID Checks"),
                ])
                .about("Add a new DID Contact (Will replace an existing contact if it exists)")
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove an existing DID Contact")
                .group(
                    clap::ArgGroup::new("remove-by")
                        .args(["did", "alias"])
                        .required(true)
                        .multiple(false),
                )
                .args([
                    Arg::new("did")
                        .short('d')
                        .long("did")
                        .help("DID of the contact to remove")
                        .required(true),
                    Arg::new("alias")
                        .short('a')
                        .long("alias")
                        .help("alias for the contact to remove"),
                ])
                .arg_required_else_help(true),
        )
        .arg_required_else_help(true);

    // Relationship management
    let relationships_subcommand = Command::new("relationships")
        .about("Manage relationships")
        .subcommand(Command::new("list").about("List Relationships"))
        .subcommand(
            Command::new("request")
                .args([
                    Arg::new("respondent")
                        .short('d')
                        .long("respondent")
                        .help("Contact alias or DID of the respondent to this relationship request")
                        .required(true),
                    Arg::new("alias")
                        .short('a')
                        .long("alias")
                        .help("Alias for the respondent DID")
                        .required(true),
                    Arg::new("reason")
                        .short('r')
                        .long("reason")
                        .help("Optional Reason for requesting relationship"),
                    Arg::new("generate-did")
                        .short('g')
                        .long("generate-did")
                        .help("Generate a new local relationship DID for this relationship request")
                        .default_value("false")
                        .action(ArgAction::SetTrue),
                ])
                .about("Request a new relationship")
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("ping")
                .about("Ping the remote end of an established connection.")
                .arg(
                    Arg::new("remote")
                        .short('r')
                        .long("remote")
                        .help("DID or contact alias to ping"),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a relationship")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("remote").short('r').long("remote").help(
                        "DID or alias of the remote DID of the relationship you want to remove",
                    ),
                ),
        )
        .arg_required_else_help(true);

    // Tasks management
    let tasks_subcommand = Command::new("tasks")
        .about("Manage tasks")
        .subcommand(Command::new("list").about("List known tasks"))
        .subcommand(Command::new("fetch").about("Fetch new tasks"))
        .subcommand(
            Command::new("remove")
                .about("Remove task")
                .arg(Arg::new("id").short('i').long("id").help("Task ID"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("interact")
                .about("Interact with tasks")
                .arg(Arg::new("id").short('i').long("id").help("Task ID")),
        )
        .subcommand(
            Command::new("clear").about("Clears tasks").args([
                Arg::new("force")
                    .long("force")
                    .help("Forced clear, will not ask to confirm!")
                    .default_value("false")
                    .action(ArgAction::SetTrue),
                Arg::new("remote")
                    .long("remote")
                    .help("Will also clear remote messages on OpenVTC Task Queue")
                    .default_value("false")
                    .action(ArgAction::SetTrue),
            ]),
        )
        .arg_required_else_help(true);

    // VRC Management
    let vrc_subcommand = Command::new("vrcs")
        .about("Manage Verified Relationship Credentials")
        .arg_required_else_help(true)
        .subcommand(Command::new("request").about("Request a VRC for a relationship"))
        .subcommand(
            Command::new("list")
                .about("List Verifiable Relationship Credentials")
                .arg(
                    Arg::new("remote")
                        .long("remote")
                        .short('r')
                        .help("Show VRC's for a remote DID/Alias relationship"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show a Verifiable Relationship Credential")
                .arg(Arg::new("id").help("VRC ID to show").required(true)),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a Verifiable Relationship Credential")
                .arg(Arg::new("id").help("VRC ID to remove").required(true)),
        );

    // Kernel Maintainers
    let maintainers_subcommand = Command::new("maintainers")
        .about("Known Maintainers")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list").about("List known Maintainers who can validate other developers"),
        );

    // Full CLI Set
    Command::new("openvtc")
        .about("First Person Project")
        .subcommand_required(true)
        .arg_required_else_help(true)
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
        .subcommand(Command::new("logs").about("Displays log information"))
        .subcommand(Command::new("status").about("Displays status of the openvtc tool"))
        .subcommand(
            Command::new("setup")
                .about("Initial configuration of the openvtc tool")
                .subcommand(
                    Command::new("import").about("Import settings").args([
                        Arg::new("file")
                            .short('f')
                            .long("file")
                            .default_value("export.openvtc")
                            .help("File containing exported settings"),
                        Arg::new("passphrase")
                            .short('p')
                            .long("passphrase")
                            .help("Passphrase to unlock the exported settings with"),
                    ]),
                ),
        )
        .subcommands([
            export_subcommand,
            contacts_subcommand,
            relationships_subcommand,
            tasks_subcommand,
            vrc_subcommand,
            maintainers_subcommand,
        ])
}
