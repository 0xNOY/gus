use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Select};
use console::Term;

use crate::user::User;

pub fn select_user<'a>(users: &'a [&'a User]) -> Result<Option<&'a User>> {
    if users.is_empty() {
        return Ok(None);
    }

    let items: Vec<String> = users
        .iter()
        .map(|user| format!("{} ({}) <{}>", user.name, user.id, user.email))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a user")
        .items(&items)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    Ok(selection.map(|idx| users[idx]))
} 