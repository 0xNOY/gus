use anyhow::Result;

mod auto_switch;
mod cli;
mod config;
mod gus;
mod shell;
mod sshkey;
mod tui;
mod user;

fn main() -> Result<()> {
    cli::run()
}
