#![cfg(any(target_os = "linux", target_os = "freebsd"))]

use std::{fs, path::Path, process::Command};

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
