use std::str::FromStr;

use gus_ipc::{
    BrokerError, BrokerProviderMessage, BrokerShimMessage, Digest32, ErrorCode, ErrorPhase,
    InteractionMode, MAX_FRAME_BYTES, OperationPresentation, ProfilePresentation,
    ProviderCapability, ProviderKind, ProviderRegistrationRequest, ProviderRequest,
    ProviderRequestFrame, RemediationAction, RepositoryPresentation, ResolveSelectionRequest,
    RetryDisposition, SelectionPrompt, SelectionScopePresentation, ShimRequest, ShimRequestFrame,
    WireFrame, decode_provider_request, decode_provider_response, decode_shim_request,
    encode_provider_request, encode_provider_response, encode_shim_request, encode_shim_response,
};
use gus_profile::ProfileId;

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn profile_id(value: &str) -> ProfileId {
    ProfileId::try_from(value.to_owned()).expect("valid profile id")
}

#[test]
fn shim_request_has_a_stable_directional_wire_shape() {
    let request_id = "7f86b094-6af1-44e6-b967-6050fe782a89"
        .parse()
        .expect("valid request id");
    let request = ResolveSelectionRequest::new(
        digest(0x11),
        digest(0x22),
        OperationPresentation::Commit,
        InteractionMode::Foreground,
        None,
    );
    let frame = WireFrame::correlated(request_id, ShimRequest::ResolveSelection(request))
        .expect("valid frame");
    let encoded = encode_shim_request(&frame).expect("encodes");
    let expected = include_bytes!("fixtures/shim-resolve-v1.json");
    assert_eq!(
        encoded.as_slice(),
        expected.strip_suffix(b"\n").unwrap_or(expected)
    );
    assert_eq!(decode_shim_request(expected).expect("decodes"), frame);
}

#[test]
fn provider_prompt_has_only_bounded_presentation_data() {
    let request_id = "34de3f03-36f9-49cb-8b1d-f090991b854e"
        .parse()
        .expect("valid request id");
    let registration_id = "43d84d56-2cc8-41d0-a3b0-1146cb337eac"
        .parse()
        .expect("valid registration id");
    let repository =
        RepositoryPresentation::new(digest(0x33), "gus".into()).expect("valid repository");
    let profile = ProfilePresentation::new(
        profile_id("work"),
        "Work profile".into(),
        Some("dev@example.invalid".into()),
    )
    .expect("valid presentation");
    let prompt = SelectionPrompt::new(
        registration_id,
        7,
        SelectionScopePresentation::IdeWindow,
        repository,
        OperationPresentation::Push,
        vec![profile],
        30_000,
    )
    .expect("valid prompt");
    let frame = WireFrame::correlated(request_id, BrokerProviderMessage::SelectionPrompt(prompt))
        .expect("valid frame");
    let encoded = encode_provider_response(&frame).expect("encodes");
    let expected = include_bytes!("fixtures/provider-prompt-v1.json");
    assert_eq!(
        encoded.as_slice(),
        expected.strip_suffix(b"\n").unwrap_or(expected)
    );
    assert_eq!(decode_provider_response(expected).expect("decodes"), frame);

    let wire = String::from_utf8(encoded).expect("JSON is UTF-8");
    for forbidden in [
        "capability",
        "private_key",
        "password",
        "credential_backend",
        "peer_pid",
        "session_leader",
    ] {
        assert!(!wire.contains(forbidden), "wire leaked {forbidden}");
    }
}

#[test]
fn wrong_version_unknown_fields_and_direction_are_rejected() {
    let fixture = include_bytes!("fixtures/shim-resolve-v1.json");
    let wrong_version = String::from_utf8(fixture.to_vec())
        .expect("fixture is UTF-8")
        .replacen("\"protocol_version\":1", "\"protocol_version\":2", 1);
    assert!(decode_shim_request(wrong_version.as_bytes()).is_err());

    let unknown = String::from_utf8(fixture.to_vec())
        .expect("fixture is UTF-8")
        .replacen("\"request_id\"", "\"unexpected\":true,\"request_id\"", 1);
    assert!(decode_shim_request(unknown.as_bytes()).is_err());
    assert!(decode_provider_request(fixture).is_err());
}

#[test]
fn framing_limits_are_checked_before_and_after_json() {
    assert!(decode_shim_request(&[]).is_err());
    assert!(decode_shim_request(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());

    let fixture = include_bytes!("fixtures/shim-resolve-v1.json");
    let mut trailing = fixture.to_vec();
    trailing.extend_from_slice(b"{}");
    assert!(decode_shim_request(&trailing).is_err());
}

#[test]
fn request_ids_require_canonical_uuid_v4_and_are_fresh() {
    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "7F86B094-6AF1-44E6-B967-6050FE782A89",
        "7f86b094-6af1-14e6-b967-6050fe782a89",
        "7f86b0946af144e6b9676050fe782a89",
    ] {
        assert!(gus_ipc::RequestId::from_str(invalid).is_err());
    }

    let first = gus_ipc::RequestId::generate().expect("CSPRNG available");
    let second = gus_ipc::RequestId::generate().expect("CSPRNG available");
    assert_ne!(first, second);
    assert_eq!(first.to_string().as_bytes()[14], b'4');
}

#[test]
fn provider_metadata_is_bounded_and_requires_quick_pick() {
    assert!(
        ProviderRegistrationRequest::new(
            ProviderKind::Vscode,
            "window\nspoof".into(),
            digest(1),
            vec![digest(2)],
            vec![ProviderCapability::ProfileQuickPick],
        )
        .is_err()
    );
    assert!(
        ProviderRegistrationRequest::new(
            ProviderKind::Vscode,
            "window-1".into(),
            digest(1),
            vec![digest(2)],
            vec![ProviderCapability::Status],
        )
        .is_err()
    );
    assert!(
        ProviderRegistrationRequest::new(
            ProviderKind::Vscode,
            "window-1".into(),
            digest(1),
            vec![digest(2), digest(2)],
            vec![ProviderCapability::ProfileQuickPick],
        )
        .is_err()
    );
}

#[test]
fn serde_cannot_bypass_nested_validation() {
    let fixture = include_bytes!("fixtures/provider-prompt-v1.json");
    let invalid = String::from_utf8(fixture.to_vec())
        .expect("fixture is UTF-8")
        .replacen("Work profile", "Work\\nprofile", 1);
    assert!(decode_provider_response(invalid.as_bytes()).is_err());

    let bidi = String::from_utf8(fixture.to_vec())
        .expect("fixture is UTF-8")
        .replacen("Work profile", "Work\u{202e}profile", 1);
    assert!(decode_provider_response(bidi.as_bytes()).is_err());
}

#[test]
fn duplicate_profile_ids_are_rejected_even_with_different_labels() {
    let fixture = include_bytes!("fixtures/provider-prompt-v1.json");
    let text = String::from_utf8(fixture.to_vec()).expect("fixture is UTF-8");
    let original =
        r#"{"profile_id":"work","display_name":"Work profile","email":"dev@example.invalid"}"#;
    let replacement =
        format!(r#"{original},{{"profile_id":"work","display_name":"Spoof","email":null}}"#);
    let duplicate = text.replacen(original, &replacement, 1);
    assert_ne!(duplicate, text, "fixture replacement must remain effective");
    assert!(decode_provider_response(duplicate.as_bytes()).is_err());
}

#[test]
fn stable_error_code_and_phase_contract_are_serialized_exactly() {
    let request_id = "44a79515-382e-4a5d-9429-01d20596583c"
        .parse()
        .expect("valid request id");
    let diagnostic_id = "b50f6e17-00b0-4dab-97bb-327a346d0bd1"
        .parse()
        .expect("valid diagnostic id");
    let error = BrokerError::new(
        ErrorCode::GusEProfileRequired,
        ErrorPhase::Preflight,
        RetryDisposition::AfterSelection,
        diagnostic_id,
        false,
        RemediationAction::SelectProfile,
    )
    .expect("valid error");
    let frame =
        WireFrame::correlated(request_id, BrokerShimMessage::Error(error)).expect("valid frame");
    let encoded = encode_shim_response(&frame).expect("encodes");
    let text = String::from_utf8(encoded).expect("JSON is UTF-8");
    assert!(text.contains(r#""code":"GUS_E_PROFILE_REQUIRED""#));
    assert!(text.contains(r#""phase":"preflight""#));

    let invalid_provider_phase = text
        .replace(r#""phase":"preflight""#, r#""phase":"provider""#)
        .replace(r#""real_git_started":false"#, r#""real_git_started":true"#);
    assert!(gus_ipc::decode_shim_response(invalid_provider_phase.as_bytes()).is_err());
}

#[test]
fn each_direction_round_trips_only_its_own_message_family() {
    let registration = ProviderRegistrationRequest::new(
        ProviderKind::Vscode,
        "window-1".into(),
        digest(1),
        vec![digest(2)],
        vec![
            ProviderCapability::ProfileQuickPick,
            ProviderCapability::Status,
        ],
    )
    .expect("valid registration");
    let provider_frame =
        ProviderRequestFrame::new(ProviderRequest::Register(registration)).expect("valid frame");
    let encoded = encode_provider_request(&provider_frame).expect("encodes");
    assert_eq!(
        decode_provider_request(&encoded).expect("provider request"),
        provider_frame
    );
    assert!(decode_shim_request(&encoded).is_err());

    let shim_frame =
        ShimRequestFrame::new(ShimRequest::Status(gus_ipc::StatusRequest::new(digest(9))))
            .expect("valid frame");
    let encoded = encode_shim_request(&shim_frame).expect("encodes");
    assert_eq!(
        decode_shim_request(&encoded).expect("shim request"),
        shim_frame
    );
    assert!(decode_provider_request(&encoded).is_err());
}
