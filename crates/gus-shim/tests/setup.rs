#![cfg(any(target_os = "linux", target_os = "freebsd"))]

use sha2::{Digest as _, Sha256};
use std::{fs, io::Write as _, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

fn gus() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gus"))
}

fn system_git_directory() -> &'static Path {
    #[cfg(target_os = "linux")]
    return Path::new("/usr/bin");
    #[cfg(target_os = "freebsd")]
    return Path::new("/usr/local/bin");
}

fn test_path(target: &Path) -> std::ffi::OsString {
    std::env::join_paths([target, system_git_directory()]).expect("test PATH")
}

fn test_path_with_missing_entry(target: &Path) -> std::ffi::OsString {
    std::env::join_paths([
        target,
        target.join("optional-tool-not-installed").as_path(),
        system_git_directory(),
    ])
    .expect("test PATH with missing entry")
}

fn digest(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read digest fixture"))
    )
}

#[test]
fn setup_activates_doctor_verifies_and_uninstall_restores_real_git() {
    let target = tempfile::tempdir().expect("temporary install directory");
    let path = test_path(target.path());

    let installed = gus()
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("install Git shim");
    assert!(
        installed.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(target.path().join("git").is_file());
    assert!(target.path().join(".gus-git-shim-owner-v1").is_file());

    let repeated = gus()
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("repeat idempotent setup");
    assert!(
        repeated.status.success(),
        "repeated setup failed: {}",
        String::from_utf8_lossy(&repeated.stderr)
    );

    let doctor = gus()
        .arg("doctor")
        .env("PATH", &path)
        .output()
        .expect("verify active shim");
    assert!(
        doctor.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );

    let removed = gus()
        .arg("uninstall-shim")
        .env("PATH", &path)
        .output()
        .expect("uninstall Git shim");
    assert!(removed.status.success());
    assert!(!target.path().join("git").exists());
    assert!(!target.path().join(".gus-git-shim-owner-v1").exists());
}

#[test]
fn setup_never_overwrites_an_unowned_git() {
    let target = tempfile::tempdir().expect("temporary install directory");
    let existing = target.path().join("git");
    fs::write(&existing, b"third-party wrapper\n").expect("write existing Git wrapper");
    let path = test_path(target.path());

    let rejected = gus()
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", path)
        .output()
        .expect("reject existing Git wrapper");

    assert!(!rejected.status.success());
    assert_eq!(
        fs::read(existing).expect("read preserved wrapper"),
        b"third-party wrapper\n"
    );
}

#[test]
fn setup_rejects_a_group_or_world_writable_target() {
    let target = tempfile::tempdir().expect("temporary install directory");
    fs::set_permissions(target.path(), fs::Permissions::from_mode(0o777))
        .expect("make target unsafe");
    let path = test_path(target.path());

    let rejected = gus()
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", path)
        .output()
        .expect("reject unsafe target");

    assert!(!rejected.status.success());
    assert!(!target.path().join("git").exists());
}

#[test]
fn dry_run_changes_no_files() {
    let target = tempfile::tempdir().expect("temporary install directory");
    let path = test_path(target.path());

    let dry_run = gus()
        .args(["setup", "--dry-run", "--target-dir"])
        .arg(target.path())
        .env("PATH", path)
        .output()
        .expect("dry-run setup");

    assert!(dry_run.status.success());
    assert_eq!(fs::read_dir(target.path()).expect("read target").count(), 0);
}

#[test]
fn nonexistent_absolute_path_entries_do_not_block_setup() {
    let target = tempfile::tempdir().expect("temporary install directory");
    let path = test_path_with_missing_entry(target.path());

    let dry_run = gus()
        .args(["setup", "--dry-run", "--target-dir"])
        .arg(target.path())
        .env("PATH", path)
        .output()
        .expect("dry-run setup with missing PATH entry");

    assert!(
        dry_run.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
}

#[test]
fn setup_upgrades_an_owned_unmodified_shim() {
    let bundle = tempfile::tempdir().expect("temporary bundle");
    let target = tempfile::tempdir().expect("temporary install directory");
    let bundled_gus = bundle.path().join("gus");
    let bundled_shim = bundle.path().join("gus-git-shim");
    fs::copy(env!("CARGO_BIN_EXE_gus"), &bundled_gus).expect("copy gus CLI");
    fs::copy(env!("CARGO_BIN_EXE_gus-git-shim"), &bundled_shim).expect("copy Git shim");
    fs::set_permissions(&bundled_gus, fs::Permissions::from_mode(0o755)).expect("chmod gus");
    fs::set_permissions(&bundled_shim, fs::Permissions::from_mode(0o755)).expect("chmod shim");
    let path = test_path(target.path());

    let initial = Command::new(&bundled_gus)
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("initial setup");
    assert!(initial.status.success());
    let before = fs::read(target.path().join("git")).expect("read initial shim");

    fs::OpenOptions::new()
        .append(true)
        .open(&bundled_shim)
        .expect("open bundled shim for version fixture")
        .write_all(b"\0GUS-UPDATE-FIXTURE")
        .expect("append harmless ELF fixture bytes");
    let updated = Command::new(&bundled_gus)
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("update setup");
    assert!(
        updated.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let after = fs::read(target.path().join("git")).expect("read updated shim");
    assert_ne!(before, after);
    assert!(after.ends_with(b"\0GUS-UPDATE-FIXTURE"));
    assert!(!target.path().join(".gus-git-shim-update-v1").exists());
    assert!(!target.path().join(".gus-git-shim-previous-v1").exists());
}

#[test]
fn setup_recovers_an_update_interrupted_after_shim_activation() {
    let bundle = tempfile::tempdir().expect("temporary bundle");
    let target = tempfile::tempdir().expect("temporary install directory");
    let bundled_gus = bundle.path().join("gus");
    let bundled_shim = bundle.path().join("gus-git-shim");
    fs::copy(env!("CARGO_BIN_EXE_gus"), &bundled_gus).expect("copy gus CLI");
    fs::copy(env!("CARGO_BIN_EXE_gus-git-shim"), &bundled_shim).expect("copy Git shim");
    fs::set_permissions(&bundled_gus, fs::Permissions::from_mode(0o755)).expect("chmod gus");
    fs::set_permissions(&bundled_shim, fs::Permissions::from_mode(0o755)).expect("chmod shim");
    let path = test_path(target.path());
    let initial = Command::new(&bundled_gus)
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("initial setup");
    assert!(initial.status.success());

    let active = target.path().join("git");
    let owner = target.path().join(".gus-git-shim-owner-v1");
    let backup = target.path().join(".gus-git-shim-previous-v1");
    let journal = target.path().join(".gus-git-shim-update-v1");
    let old_digest = digest(&active);
    fs::OpenOptions::new()
        .append(true)
        .open(&bundled_shim)
        .expect("open bundled shim")
        .write_all(b"\0GUS-RECOVERY-FIXTURE")
        .expect("append recovery fixture");
    let new_digest = digest(&bundled_shim);
    fs::write(&journal, format!("old={old_digest}\nnew={new_digest}\n"))
        .expect("write update journal");
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).expect("chmod journal");
    fs::hard_link(&active, &backup).expect("retain previous shim");
    let staged = target.path().join("interrupted-new-shim");
    fs::copy(&bundled_shim, &staged).expect("stage interrupted update");
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).expect("chmod staged shim");
    fs::rename(&staged, &active).expect("activate interrupted update");
    assert_eq!(
        fs::read_to_string(&owner).expect("read old owner"),
        format!("sha256={old_digest}\n")
    );

    let recovered = Command::new(&bundled_gus)
        .args(["setup", "--target-dir"])
        .arg(target.path())
        .env("PATH", &path)
        .output()
        .expect("recover update");
    assert!(
        recovered.status.success(),
        "recovery failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(digest(&active), new_digest);
    assert_eq!(
        fs::read_to_string(owner).expect("read recovered owner"),
        format!("sha256={new_digest}\n")
    );
    assert!(!backup.exists());
    assert!(!journal.exists());
}
