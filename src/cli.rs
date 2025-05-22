use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;
use rpassword::read_password;
use std::io::{self, Write};
use std::path::PathBuf;
use comfy_table::{Table, ContentArrangement};

use crate::gus::GitUserSwitcher;
use crate::user::User;
use crate::tui;

static DEFAULT_CONFIG_PATH: Lazy<PathBuf> =
    Lazy::new(|| dirs::home_dir().unwrap().join(".config/gus/config.toml"));

#[derive(Parser)]
#[clap(name = env!("CARGO_PKG_NAME"), version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
struct Cli {
    #[clap(subcommand)]
    subcmd: Subcommands,

    /// The path to the config file
    #[clap(long, short, default_value = &DEFAULT_CONFIG_PATH.to_str().unwrap())]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Subcommands {
    /// Echo a shell script to setup the shell for this app
    Setup,

    /// Add a new user
    Add {
        #[clap(flatten)]
        user: User,
    },

    /// Remove a user
    Remove {
        /// The ID of the user to remove
        id: String,
    },

    /// Switch to a user
    Set {
        /// The ID of the user to switch to
        #[clap(required = false)]
        id: Option<String>,
    },

    /// Show the current user
    Current,

    /// List all users
    List {
        /// Output in a simple, parseable format
        #[clap(long, short)]
        simple: bool,
    },

    /// Echo a public ssh key
    Key {
        /// The ID of the user to get the key for
        id: String,
    },

    /// Auto-switch related commands
    #[clap(subcommand)]
    AutoSwitch(AutoSwitchCommands),
}

#[derive(Subcommand)]
enum AutoSwitchCommands {
    /// Enable auto-switch feature
    Enable,

    /// Disable auto-switch feature
    Disable,

    /// Add a new auto-switch pattern
    Add {
        /// The glob pattern to match directories
        pattern: String,
        /// The user ID to switch to when pattern matches
        user_id: String,
    },

    /// Remove an auto-switch pattern
    Remove {
        /// The pattern to remove
        pattern: String,
    },

    /// List all auto-switch patterns
    List,

    /// Check and perform auto-switch based on current directory
    Check,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    let mut gus = GitUserSwitcher::from(&cli.config);

    match cli.subcmd {
        Subcommands::Setup => {
            println!("{}", gus.get_setup_script())
        }
        Subcommands::Add { user } => {
            ensure!(
                !gus.exists_user(&user.id),
                "user with id '{}' already exists",
                user.id
            );

            let is_required_sshkey_passphrase = if let Some(sshkey_path) = &user.sshkey_path {
                !sshkey_path.exists()
            } else {
                true
            };

            let sshkey_passphrase = if is_required_sshkey_passphrase {
                let msg_suffix = if gus.config.min_sshkey_passphrase_length > 0 {
                    format!(
                        "(at least {} chars required)",
                        gus.config.min_sshkey_passphrase_length
                    )
                } else {
                    "(10+ chars recommended)".to_string()
                };
                print!("Enter new ssh key passphrase {}: ", msg_suffix);
                io::stdout().flush().unwrap();
                let pass = read_password().context("failed to read ssh key passphrase")?;
                ensure!(
                    pass.len() >= gus.config.min_sshkey_passphrase_length,
                    "ssh key passphrase must be at least {} characters",
                    gus.config.min_sshkey_passphrase_length
                );
                Some(pass)
            } else {
                None
            };

            gus.add_user(user, sshkey_passphrase.as_deref())?;
        }
        Subcommands::Remove { id } => {
            gus.remove_user(&id)?;
        }
        Subcommands::Set { id } => {
            if let Some(id) = id {
                gus.switch_user(&id)?;
            } else {
                let users = gus.list_users();
                if let Some(user) = tui::select_user(&users)? {
                    gus.switch_user(&user.id)?;
                } else {
                    println!("No users available");
                }
            }
        }
        Subcommands::Current => {
            let user = gus.get_current_user().context("no current user")?;
            println!("{}\t{}\t{}\t{}", user.id, user.name, user.email, user.get_sshkey_path(&gus.config.default_sshkey_dir)
            .to_string_lossy());
        }
        Subcommands::List { simple } => {
            let users = gus.list_users();
            if simple {
                for user in users {
                    println!("{}\t{}\t{}\t{}", user.id, user.name, user.email, user.get_sshkey_path(&gus.config.default_sshkey_dir)
                    .to_string_lossy());
                }
            } else {
                let mut table = Table::new();
                table
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec!["ID", "Name", "Email", "SSH Key"])
                    .load_preset(comfy_table::presets::UTF8_FULL);

                for user in users {
                    let sshkey = user.get_sshkey_path(&gus.config.default_sshkey_dir)
                        .to_string_lossy().to_string();
                    table.add_row(vec![
                        &user.id,
                        &user.name,
                        &user.email,
                        &sshkey,
                    ]);
                }

                println!("{}", table);
            }
        }
        Subcommands::Key { id } => {
            let pubkey = gus.get_public_sshkey(&id)?;
            print!("{}", pubkey);
        }
        Subcommands::AutoSwitch(cmd) => match cmd {
            AutoSwitchCommands::Enable => {
                gus.enable_auto_switch()?;
                println!("Auto-switch feature enabled");
            }
            AutoSwitchCommands::Disable => {
                gus.disable_auto_switch()?;
                println!("Auto-switch feature disabled");
            }
            AutoSwitchCommands::Add { pattern, user_id } => {
                gus.add_auto_switch_pattern(&pattern, &user_id)?;
                println!("Added auto-switch pattern: {} -> {}", pattern, user_id);
            }
            AutoSwitchCommands::Remove { pattern } => {
                if gus.remove_auto_switch_pattern(&pattern)? {
                    println!("Removed auto-switch pattern: {}", pattern);
                } else {
                    println!("Pattern not found: {}", pattern);
                }
            }
            AutoSwitchCommands::List => {
                let patterns = gus.list_auto_switch_patterns();
                if patterns.is_empty() {
                    println!("No auto-switch patterns configured");
                } else {
                    println!("Auto-switch patterns:");
                    for (pattern, user_id) in patterns {
                        println!("  {} -> {}", pattern, user_id);
                    }
                }
            }
            AutoSwitchCommands::Check => {
                gus.check_auto_switch()?;
            }
        },
    }

    Ok(())
}
