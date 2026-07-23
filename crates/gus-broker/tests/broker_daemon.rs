#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use gus_broker::connect_published_provider;
use gus_ipc::{
    BrokerProviderMessage, BrokerShimMessage, Digest32, Generation, OperationPresentation,
    ProviderCapability, ProviderDecision, ProviderKind, ProviderRegistrationRequest,
    ProviderRequestFrame, ProviderSelectionDecision, ResolveSelectionRequest, ShimRequest,
    ShimRequestFrame, read_provider_response, read_shim_response, write_provider_request,
    write_shim_request,
};
use gus_profile::ProfileId;
use tempfile::TempDir;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn ide_sibling_processes_complete_one_brokered_selection() {
    if std::env::var_os("GUS_DAEMON_HELPER_ROLE").is_some() {
        return;
    }
    let fixture = Fixture::new();
    let mut broker = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_gus-broker"))
            .env("GUS_RUNTIME_DIR", fixture.runtime())
            .env("GUS_PROFILE_STORE", fixture.profile_store())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    wait_for_path(&fixture.runtime().join("provider.current"));

    let executable = std::env::current_exe().expect("test executable");
    let ready = fixture.root().join("provider-ready");
    let mut provider = ChildGuard::spawn(
        Command::new(&executable)
            .arg("--exact")
            .arg("provider_helper")
            .arg("--nocapture")
            .env("GUS_DAEMON_HELPER_ROLE", "provider")
            .env("GUS_RUNTIME_DIR", fixture.runtime())
            .env("GUS_PROVIDER_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    );
    wait_for_path(&ready);

    let status = Command::new(executable)
        .arg("--exact")
        .arg("shim_helper")
        .arg("--nocapture")
        .env("GUS_DAEMON_HELPER_ROLE", "shim")
        .env("GUS_RUNTIME_DIR", fixture.runtime())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("run shim helper");
    assert!(status.success(), "shim helper failed: {status}");

    let provider_status = provider.wait().expect("wait for provider helper");
    assert!(
        provider_status.success(),
        "provider helper failed: {provider_status}"
    );
    broker.kill();
}

#[test]
fn a_different_ide_host_cannot_use_the_registered_provider() {
    if std::env::var_os("GUS_DAEMON_HELPER_ROLE").is_some() {
        return;
    }
    let fixture = Fixture::new();
    let mut broker = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_gus-broker"))
            .env("GUS_RUNTIME_DIR", fixture.runtime())
            .env("GUS_PROFILE_STORE", fixture.profile_store())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    );
    wait_for_path(&fixture.runtime().join("provider.current"));

    let executable = std::env::current_exe().expect("test executable");
    let ready = fixture.root().join("provider-ready");
    let mut provider = ChildGuard::spawn(
        Command::new(&executable)
            .arg("--exact")
            .arg("provider_helper")
            .arg("--nocapture")
            .env("GUS_DAEMON_HELPER_ROLE", "provider")
            .env("GUS_RUNTIME_DIR", fixture.runtime())
            .env("GUS_PROVIDER_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    );
    wait_for_path(&ready);

    let status = Command::new(executable)
        .arg("--exact")
        .arg("foreign_host_helper")
        .arg("--nocapture")
        .env("GUS_DAEMON_HELPER_ROLE", "foreign_host")
        .env("GUS_RUNTIME_DIR", fixture.runtime())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("run foreign host helper");
    assert!(status.success(), "foreign host helper failed: {status}");
    provider.kill();
    broker.kill();
}

#[test]
fn provider_helper() {
    if std::env::var_os("GUS_DAEMON_HELPER_ROLE").as_deref()
        != Some(std::ffi::OsStr::new("provider"))
    {
        return;
    }
    let runtime = required_path("GUS_RUNTIME_DIR");
    let mut stream =
        connect_published_provider(runtime, IO_TIMEOUT, IO_TIMEOUT).expect("connect provider");
    let registration = ProviderRegistrationRequest::new(
        ProviderKind::Vscode,
        "daemon-test-window".to_owned(),
        vec![ProviderCapability::ProfileQuickPick],
    )
    .expect("registration");
    let registration =
        ProviderRequestFrame::registration(registration).expect("registration frame");
    write_provider_request(&mut stream, &registration).expect("write registration");
    let accepted = read_provider_response(&mut stream).expect("read registration response");
    let BrokerProviderMessage::Registered(accepted) = accepted.message() else {
        panic!("unexpected registration response");
    };
    fs::write(required_path("GUS_PROVIDER_READY"), b"ready").expect("publish provider readiness");

    let prompt = read_provider_response(&mut stream).expect("read selection prompt");
    let BrokerProviderMessage::SelectionPrompt(selection) = prompt.message() else {
        panic!("unexpected provider command");
    };
    let id = ProfileId::try_from("alice".to_owned()).expect("profile id");
    assert!(
        selection
            .profiles()
            .iter()
            .any(|profile| profile.profile_id() == &id)
    );
    let decision = ProviderSelectionDecision::new(
        accepted.registration_id(),
        accepted.provider_generation(),
        selection.selection_generation(),
        ProviderDecision::Selected(id),
    )
    .expect("selection decision");
    let response = ProviderRequestFrame::selection_response(prompt.request_id(), decision)
        .expect("selection response");
    write_provider_request(&mut stream, &response).expect("write selection response");
    let acknowledgement = read_provider_response(&mut stream).expect("read acknowledgement");
    assert!(matches!(
        acknowledgement.message(),
        BrokerProviderMessage::Acknowledged
    ));
}

#[test]
fn shim_helper() {
    if std::env::var_os("GUS_DAEMON_HELPER_ROLE").as_deref() != Some(std::ffi::OsStr::new("shim")) {
        return;
    }
    let runtime = required_path("GUS_RUNTIME_DIR");
    let mut stream =
        connect_published_provider(runtime, IO_TIMEOUT, IO_TIMEOUT).expect("connect shim");
    let request = ResolveSelectionRequest::new(
        Digest32::from_bytes([4; 32]),
        Digest32::from_bytes([3; 32]),
        OperationPresentation::Commit,
        None,
    );
    let request =
        ShimRequestFrame::request(ShimRequest::ResolveSelection(request)).expect("shim request");
    write_shim_request(&mut stream, &request).expect("write shim request");
    let response = read_shim_response(&mut stream).expect("read shim response");
    assert_eq!(response.request_id(), request.request_id());
    if std::env::var_os("GUS_EXPECT_PROVIDER_UNAVAILABLE").is_some() {
        let BrokerShimMessage::Error(error) = response.message() else {
            panic!("an unrelated IDE host unexpectedly used the provider");
        };
        assert_eq!(error.code(), gus_ipc::ErrorCode::GusEProviderUnavailable);
    } else {
        let BrokerShimMessage::Resolved(resolved) = response.message() else {
            panic!("unexpected shim response");
        };
        assert_eq!(resolved.profile_id().as_str(), "alice");
        assert_eq!(resolved.profile_generation(), Generation::new(1).unwrap());
    }
}

#[test]
fn foreign_host_helper() {
    if std::env::var_os("GUS_DAEMON_HELPER_ROLE").as_deref()
        != Some(std::ffi::OsStr::new("foreign_host"))
    {
        return;
    }
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("shim_helper")
        .arg("--nocapture")
        .env("GUS_DAEMON_HELPER_ROLE", "shim")
        .env("GUS_EXPECT_PROVIDER_UNAVAILABLE", "1")
        .env("GUS_RUNTIME_DIR", required_path("GUS_RUNTIME_DIR"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("run foreign shim");
    assert!(status.success(), "foreign shim failed: {status}");
}

struct Fixture {
    root: TempDir,
    runtime: PathBuf,
    profile_store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary fixture");
        let runtime = root.path().join("runtime");
        fs::create_dir(&runtime).expect("runtime directory");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))
            .expect("runtime permissions");
        let profile_store = root.path().join("profiles.toml");
        fs::write(
            &profile_store,
            r#"version = 2
generation = 1

[profiles.alice]
id = "alice"
generation = 1

[profiles.alice.author]
name = "Alice Example"
email = "alice@example.com"

[profiles.alice.committer]
name = "Alice Example"
email = "alice@example.com"
"#,
        )
        .expect("profile store");
        fs::set_permissions(&profile_store, fs::Permissions::from_mode(0o600))
            .expect("profile permissions");
        Self {
            root,
            runtime,
            profile_store,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn runtime(&self) -> &Path {
        &self.runtime
    }

    fn profile_store(&self) -> &Path {
        &self.profile_store
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(command: &mut Command) -> Self {
        Self(Some(command.spawn().expect("spawn child")))
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.as_mut().expect("live child").wait()
    }

    fn kill(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .expect("required helper path")
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} was not published",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
