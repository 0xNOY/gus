#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt as _, process::Command};

fn gus(store: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gus"));
    command.env("GUS_PROFILE_STORE", store);
    command
}

#[test]
fn user_commands_manage_the_store_without_manual_editing() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = directory.path().join("config/gus/profiles.toml");

    let added = gus(&store)
        .args(["user", "add", "work", "Work User", "work@example.test"])
        .output()
        .expect("add profile");
    assert!(
        added.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert_eq!(added.stdout, b"Added GUS profile 'work'\n");

    let listed = gus(&store)
        .args(["user", "list"])
        .output()
        .expect("list profiles");
    assert!(listed.status.success());
    assert_eq!(listed.stdout, b"work\tWork User <work@example.test>\n");

    let duplicate = gus(&store)
        .args(["user", "add", "work", "Other User", "other@example.test"])
        .output()
        .expect("reject duplicate");
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("profile 'work' already exists"));

    let removed = gus(&store)
        .args(["user", "remove", "work"])
        .output()
        .expect("remove profile");
    assert!(removed.status.success());
    assert_eq!(removed.stdout, b"Removed GUS profile 'work'\n");

    let listed = gus(&store)
        .args(["user", "list"])
        .output()
        .expect("list empty profiles");
    assert!(listed.status.success());
    assert!(listed.stdout.is_empty());
    assert_eq!(
        fs::metadata(&store)
            .expect("profile metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn user_add_rejects_invalid_identity_without_creating_a_store() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = directory.path().join("config/gus/profiles.toml");
    let output = gus(&store)
        .args(["user", "add", "work", "Work User", "not-an-email"])
        .output()
        .expect("reject invalid profile");

    assert!(!output.status.success());
    assert!(!store.exists());
}
