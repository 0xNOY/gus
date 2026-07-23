#![cfg(unix)]

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
    time::Duration,
};

use gus_broker::PublishedUnixProviderEndpoint;
use gus_ipc::{
    BrokerProviderMessage, Digest32, Generation, ProviderCapability, ProviderKind,
    ProviderRegistrationRequest, ProviderRequestFrame, read_provider_response,
    write_provider_request,
};

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

#[test]
fn native_bridge_relays_provider_records_over_authenticated_stdio() {
    let runtime = tempfile::Builder::new()
        .prefix("gpb-")
        .tempdir_in("/tmp")
        .expect("temporary runtime");
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    let published = PublishedUnixProviderEndpoint::bind(
        runtime.path(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .expect("publish endpoint");

    let mut child = Command::new(env!("CARGO_BIN_EXE_gus-provider-bridge"))
        .arg("--runtime-dir")
        .arg(runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn provider bridge");
    let mut child_input = child.stdin.take().expect("bridge stdin");
    let mut child_output = child.stdout.take().expect("bridge stdout");
    let registration = ProviderRequestFrame::registration(
        ProviderRegistrationRequest::new(
            ProviderKind::Vscode,
            "window-1".into(),
            vec![
                ProviderCapability::ProfileQuickPick,
                ProviderCapability::Status,
            ],
        )
        .expect("registration"),
    )
    .expect("registration frame");
    write_provider_request(&mut child_input, &registration).expect("write bridge stdin");
    child_input.flush().expect("flush bridge stdin");

    let connection = published
        .accept_registration()
        .expect("accept bridged registration")
        .admit(
            &[digest(2)],
            Generation::new(1).expect("generation"),
            Generation::new(7).expect("generation"),
            15_000,
        )
        .expect("admit bridged provider");
    assert_eq!(
        connection.provider_generation(),
        Generation::new(7).expect("generation")
    );

    let response = read_provider_response(&mut child_output).expect("read bridge stdout");
    assert_eq!(response.request_id(), registration.request_id());
    assert!(matches!(
        response.message(),
        BrokerProviderMessage::Registered(_)
    ));
    drop(child_input);
    let output = child.wait_with_output().expect("wait for provider bridge");
    assert!(
        output.status.success(),
        "bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
