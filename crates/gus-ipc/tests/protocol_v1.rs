use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use gus_ipc::{
    BrokerError, BrokerProviderMessage, BrokerShimMessage, Digest32, ErrorCode, ErrorDetail,
    ErrorPhase, FRAME_HEADER_BYTES, Generation, MAX_FRAME_BYTES, OperationPresentation,
    ProfilePresentation, ProtectionStatus, ProtocolErrorDetail, ProviderCapability,
    ProviderControlRequest, ProviderCorrelation, ProviderCorrelationError, ProviderDecision,
    ProviderKind, ProviderRegistrationRequest, ProviderRepositoryMembership, ProviderRequest,
    ProviderRequestFrame, ProviderResponseFrame, ProviderSelectionDecision, ProviderStatusEntry,
    ProviderStatusSnapshot, RegistrationAccepted, RemediationAction, RepositoryPresentation,
    ResolveSelectionRequest, RetryDisposition, ScopePresentation, SelectionPrompt,
    SelectionScopePresentation, ShimRequest, ShimRequestFrame, ShimResponseFrame,
    decode_frame_length, decode_provider_request, decode_provider_response, decode_shim_request,
    decode_shim_response, encode_provider_request, encode_provider_response, encode_shim_request,
    encode_shim_response,
};
use gus_profile::ProfileId;

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn generation(value: u64) -> Generation {
    Generation::new(value).expect("nonzero generation")
}

fn profile_id(value: &str) -> ProfileId {
    ProfileId::try_from(value.to_owned()).expect("valid profile id")
}

fn request_id(value: &str) -> gus_ipc::RequestId {
    value.parse().expect("valid request id")
}

fn record(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("fixture length fits u32");
    let mut record = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn payload(record: &[u8]) -> &[u8] {
    &record[FRAME_HEADER_BYTES..]
}

fn scope(kind: SelectionScopePresentation, value: u8, label: &str) -> ScopePresentation {
    ScopePresentation::new(kind, digest(value), label.into()).expect("valid scope")
}

fn repository(value: u8, label: &str) -> RepositoryPresentation {
    RepositoryPresentation::new(digest(value), label.into()).expect("valid repository")
}

fn profile(id: &str, display_name: &str) -> ProfilePresentation {
    ProfilePresentation::new(
        profile_id(id),
        display_name.into(),
        Some(format!("{id}@example.invalid")),
    )
    .expect("valid profile presentation")
}

fn provider_correlation(
    registration_id: gus_ipc::RequestId,
    provider_generation: Generation,
    repositories: Vec<Digest32>,
    capabilities: Vec<ProviderCapability>,
) -> ProviderCorrelation {
    let registration = ProviderRegistrationRequest::new(
        ProviderKind::Vscode,
        "test-editor-session".into(),
        digest(0xfe),
        repositories,
        capabilities,
    )
    .expect("registration");
    let accepted = RegistrationAccepted::new(registration_id, provider_generation, 15_000)
        .expect("accepted registration");
    ProviderCorrelation::from_registration(&registration, &accepted)
}

fn prompt(
    registration_id: gus_ipc::RequestId,
    provider_generation: Generation,
    selection_generation: Generation,
) -> SelectionPrompt {
    SelectionPrompt::new(
        registration_id,
        provider_generation,
        selection_generation,
        scope(SelectionScopePresentation::IdeWindow, 0x44, "SCM"),
        repository(0x33, "gus"),
        OperationPresentation::Push,
        vec![profile("work", "Work profile")],
        30_000,
    )
    .expect("valid prompt")
}

#[test]
fn shim_request_has_stable_family_and_wire_shape() {
    let request_id = request_id("7f86b094-6af1-44e6-b967-6050fe782a89");
    let request = ResolveSelectionRequest::new(
        digest(0x11),
        digest(0x22),
        OperationPresentation::Commit,
        None,
    );
    let generated = ShimRequestFrame::request(ShimRequest::ResolveSelection(request.clone()))
        .expect("valid request");
    assert_ne!(generated.request_id(), request_id);

    let json = include_bytes!("fixtures/shim-resolve-v1.json");
    let decoded = decode_shim_request(&record(json)).expect("fixture decodes");
    assert_eq!(decoded.request_id(), request_id);
    assert_eq!(decoded.message(), &ShimRequest::ResolveSelection(request));
    let encoded = encode_shim_request(&decoded).expect("encodes");
    assert_eq!(payload(&encoded), json.strip_suffix(b"\n").unwrap_or(json));
}

#[test]
fn provider_prompt_has_stable_bounded_presentation_shape() {
    let frame_id = request_id("34de3f03-36f9-49cb-8b1d-f090991b854e");
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let generated = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        generation(3),
        generation(7),
    ))
    .expect("valid prompt frame");
    assert_ne!(generated.request_id(), frame_id);

    let json = include_bytes!("fixtures/provider-prompt-v1.json");
    let decoded = decode_provider_response(&record(json)).expect("fixture decodes");
    assert_eq!(decoded.request_id(), frame_id);
    let BrokerProviderMessage::SelectionPrompt(decoded_prompt) = decoded.message() else {
        panic!("expected prompt");
    };
    assert_eq!(decoded_prompt.registration_id(), registration_id);
    assert_eq!(decoded_prompt.provider_generation(), generation(3));
    assert_eq!(decoded_prompt.selection_generation(), generation(7));
    assert_eq!(decoded_prompt.scope().label(), "SCM");
    assert_eq!(decoded_prompt.repository().label(), "gus");
    assert_eq!(decoded_prompt.profiles()[0].display_name(), "Work profile");
    assert_eq!(decoded_prompt.timeout_millis(), 30_000);

    let encoded = encode_provider_response(&decoded).expect("encodes");
    assert_eq!(payload(&encoded), json.strip_suffix(b"\n").unwrap_or(json));
    let wire = String::from_utf8(payload(&encoded).to_vec()).expect("payload is UTF-8");
    for forbidden in [
        "capability_handle",
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
fn every_direction_is_domain_separated_on_the_wire() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let frames = [
        encode_shim_request(
            &ShimRequestFrame::request(ShimRequest::Status(gus_ipc::StatusRequest::new(digest(1))))
                .expect("shim request"),
        )
        .expect("encode shim request"),
        encode_shim_response(
            &ShimResponseFrame::response(
                request_id("7f86b094-6af1-44e6-b967-6050fe782a89"),
                BrokerShimMessage::Cleared {
                    session_generation: generation(2),
                },
            )
            .expect("shim response"),
        )
        .expect("encode shim response"),
        encode_provider_request(
            &ProviderRequestFrame::control(ProviderRequest::Heartbeat(
                ProviderControlRequest::new(registration_id, generation(3)),
            ))
            .expect("provider request"),
        )
        .expect("encode provider request"),
        encode_provider_response(
            &ProviderResponseFrame::acknowledgement(request_id(
                "34de3f03-36f9-49cb-8b1d-f090991b854e",
            ))
            .expect("provider response"),
        )
        .expect("encode provider response"),
    ];
    for (expected_direction, frame) in frames.iter().enumerate() {
        let results = [
            decode_shim_request(frame).is_ok(),
            decode_shim_response(frame).is_ok(),
            decode_provider_request(frame).is_ok(),
            decode_provider_response(frame).is_ok(),
        ];
        assert_eq!(results.iter().filter(|result| **result).count(), 1);
        assert!(results[expected_direction]);
    }
}

#[test]
fn framing_rejects_partial_coalesced_zero_and_oversized_records() {
    assert!(decode_shim_request(&[]).is_err());
    assert!(decode_frame_length(&[0, 0, 0]).is_err());
    assert!(decode_frame_length(&[0, 0, 0, 0]).is_err());
    let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
        .expect("limit fits u32")
        .to_be_bytes();
    assert!(decode_frame_length(&oversized).is_err());

    let valid = record(include_bytes!("fixtures/shim-resolve-v1.json"));
    assert!(decode_shim_request(&valid[..valid.len() - 1]).is_err());
    let mut coalesced = valid.clone();
    coalesced.extend_from_slice(&valid);
    assert!(decode_shim_request(&coalesced).is_err());

    let mut wrong_length = valid;
    wrong_length[..FRAME_HEADER_BYTES].copy_from_slice(&1_u32.to_be_bytes());
    assert!(decode_shim_request(&wrong_length).is_err());
}

#[test]
fn request_ids_and_generations_have_cross_language_safe_canonical_forms() {
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

    assert_eq!(
        serde_json::to_string(&generation(u64::MAX)).expect("serializes"),
        format!("\"{}\"", u64::MAX)
    );
    assert_eq!(
        serde_json::from_str::<Generation>(&format!("\"{}\"", u64::MAX)).expect("max generation"),
        generation(u64::MAX)
    );
    for invalid in ["0", "01", "-1", "+1", "18446744073709551616"] {
        assert!(serde_json::from_str::<Generation>(&format!("\"{invalid}\"")).is_err());
    }
    assert!(serde_json::from_str::<Generation>("9007199254740992").is_err());
    assert_eq!(
        serde_json::to_string(&ProviderKind::JetBrains).expect("provider serializes"),
        "\"jet_brains\""
    );
}

#[test]
fn public_dto_deserialization_cannot_bypass_validation() {
    let registration = r#"{
        "kind":"vscode",
        "editor_session_id":"window\nspoof",
        "host_instance":"1111111111111111111111111111111111111111111111111111111111111111",
        "repositories":[],
        "capabilities":[]
    }"#;
    assert!(serde_json::from_str::<ProviderRegistrationRequest>(registration).is_err());

    let duplicate_membership = format!(
        r#"{{"registration_id":"43d84d56-2cc8-41d0-a3b0-1146cb337eac","provider_generation":"3","membership_generation":"4","repositories":["{0}","{0}"]}}"#,
        "22".repeat(32)
    );
    assert!(serde_json::from_str::<ProviderRepositoryMembership>(&duplicate_membership).is_err());
}

#[test]
fn unknown_fields_are_rejected_at_envelope_message_and_body_layers() {
    let fixture = String::from_utf8(
        include_bytes!("fixtures/shim-resolve-v1.json")
            .strip_suffix(b"\n")
            .unwrap_or(include_bytes!("fixtures/shim-resolve-v1.json"))
            .to_vec(),
    )
    .expect("fixture is UTF-8");
    let outer = fixture.replacen("\"request_id\"", "\"unexpected\":true,\"request_id\"", 1);
    assert!(decode_shim_request(&record(outer.as_bytes())).is_err());
    let message = fixture.replacen(
        "\"type\":\"resolve_selection\"",
        "\"unexpected\":true,\"type\":\"resolve_selection\"",
        1,
    );
    assert!(decode_shim_request(&record(message.as_bytes())).is_err());
    let body = fixture.replacen("\"plan_digest\"", "\"unexpected\":true,\"plan_digest\"", 1);
    assert!(decode_shim_request(&record(body.as_bytes())).is_err());

    let heartbeat = r#"{"protocol_version":1,"message_family":"provider_request","request_id":"7f86b094-6af1-44e6-b967-6050fe782a89","message":{"type":"heartbeat","body":{"registration_id":"43d84d56-2cc8-41d0-a3b0-1146cb337eac","provider_generation":"3","ignored":"smuggled"}}}"#;
    assert!(decode_provider_request(&record(heartbeat.as_bytes())).is_err());

    let duplicate = fixture.replacen(
        "\"protocol_version\":1",
        "\"protocol_version\":1,\"protocol_version\":1",
        1,
    );
    assert!(decode_shim_request(&record(duplicate.as_bytes())).is_err());
}

#[test]
fn error_catalog_mapping_rejects_contradictory_phase_retry_action_and_detail() {
    let diagnostic_id = request_id("b50f6e17-00b0-4dab-97bb-327a346d0bd1");
    let error = BrokerError::new(
        ErrorCode::GusEProfileRequired,
        ErrorPhase::Preflight,
        diagnostic_id,
        ErrorDetail::None,
    )
    .expect("valid catalog error");
    assert_eq!(error.retry(), RetryDisposition::AfterSelection);
    assert_eq!(error.action(), RemediationAction::SelectProfile);
    assert!(!error.real_git_started());

    assert!(
        BrokerError::new(
            ErrorCode::GusEBrokerCapacity,
            ErrorPhase::DeferredHelper,
            diagnostic_id,
            ErrorDetail::None,
        )
        .is_err()
    );
    assert!(
        BrokerError::new(
            ErrorCode::GusEInternal,
            ErrorPhase::DeferredHelper,
            diagnostic_id,
            ErrorDetail::None,
        )
        .is_err()
    );
    assert!(
        BrokerError::new(
            ErrorCode::GusEProtocolMismatch,
            ErrorPhase::Preflight,
            diagnostic_id,
            ErrorDetail::Protocol(ProtocolErrorDetail::new(1, 1)),
        )
        .is_err()
    );

    let frame = ShimResponseFrame::response(
        request_id("44a79515-382e-4a5d-9429-01d20596583c"),
        BrokerShimMessage::Error(error),
    )
    .expect("valid frame");
    let encoded = encode_shim_response(&frame).expect("encodes");
    let text = String::from_utf8(payload(&encoded).to_vec()).expect("JSON is UTF-8");
    assert!(text.contains(r#""code":"GUS_E_PROFILE_REQUIRED""#));
    let contradictory = text
        .replace(r#""retry":"after_selection""#, r#""retry":"no""#)
        .replace(
            r#""action":"select_profile""#,
            r#""action":"contact_administrator""#,
        );
    assert!(decode_shim_response(&record(contradictory.as_bytes())).is_err());
}

#[test]
fn maximum_semantic_prompt_fits_the_wire_limit() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let profiles = (0..32)
        .map(|index| {
            ProfilePresentation::new(
                profile_id(&format!("profile-{index}")),
                "\\\"".repeat(128),
                Some(format!("user{index}@{}", "x".repeat(240))),
            )
            .expect("bounded profile")
        })
        .collect();
    let prompt = SelectionPrompt::new(
        registration_id,
        generation(u64::MAX),
        generation(u64::MAX),
        scope(SelectionScopePresentation::Terminal, 3, &"\\".repeat(256)),
        repository(4, &"\\".repeat(256)),
        OperationPresentation::Commit,
        profiles,
        300_000,
    )
    .expect("semantic maximum is valid");
    let frame = ProviderResponseFrame::selection_prompt(prompt).expect("frame");
    let encoded = encode_provider_response(&frame).expect("semantic maximum must encode");
    assert!(encoded.len() <= MAX_FRAME_BYTES + FRAME_HEADER_BYTES);
}

#[test]
fn maximum_semantic_status_snapshot_fits_the_wire_limit() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let entries = (0_u8..16)
        .map(|index| {
            ProviderStatusEntry::new(
                scope(
                    SelectionScopePresentation::Terminal,
                    index + 1,
                    &"\\".repeat(256),
                ),
                repository(index + 32, &"\\".repeat(256)),
                Some(
                    ProfilePresentation::new(
                        profile_id(&format!("profile-{index}")),
                        "\\\"".repeat(128),
                        Some(format!("user{index}@{}", "x".repeat(240))),
                    )
                    .expect("bounded profile"),
                ),
                ProtectionStatus::Verified,
            )
            .expect("bounded status entry")
        })
        .collect();
    let snapshot = ProviderStatusSnapshot::new(registration_id, generation(u64::MAX), entries)
        .expect("semantic maximum is valid");
    let frame = ProviderResponseFrame::status_snapshot(snapshot).expect("status frame");
    let encoded = encode_provider_response(&frame).expect("semantic maximum must encode");
    assert!(encoded.len() <= MAX_FRAME_BYTES + FRAME_HEADER_BYTES);
}

#[test]
fn provider_correlation_consumes_one_exact_prompt_and_rejects_replay() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let provider_generation = generation(3);
    let selection_generation = generation(7);
    let now = Instant::now();
    let prompt_frame = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        selection_generation,
    ))
    .expect("prompt frame");
    let mut correlation = provider_correlation(
        registration_id,
        provider_generation,
        vec![digest(0x33)],
        vec![ProviderCapability::ProfileQuickPick],
    );
    assert!(
        correlation
            .track_prompt(&prompt_frame, now)
            .expect("tracked")
            .is_empty()
    );
    assert_eq!(
        correlation.track_prompt(&prompt_frame, now),
        Err(ProviderCorrelationError::DuplicatePrompt)
    );

    let stale = ProviderSelectionDecision::new(
        registration_id,
        provider_generation,
        generation(8),
        ProviderDecision::Selected(profile_id("work")),
    )
    .expect("stale decision");
    let stale_frame = ProviderRequestFrame::selection_response(prompt_frame.request_id(), stale)
        .expect("stale frame");
    assert_eq!(
        correlation.accept_selection(&stale_frame, now),
        Err(ProviderCorrelationError::SelectionGenerationMismatch)
    );
    assert_eq!(correlation.outstanding_prompt_count(), 1);

    let response = ProviderSelectionDecision::new(
        registration_id,
        provider_generation,
        selection_generation,
        ProviderDecision::Selected(profile_id("work")),
    )
    .expect("decision");
    let response_frame =
        ProviderRequestFrame::selection_response(prompt_frame.request_id(), response)
            .expect("response frame");
    assert!(matches!(
        correlation
            .accept_selection(&response_frame, now)
            .expect("accepted once"),
        ProviderDecision::Selected(id) if id.as_str() == "work"
    ));
    assert_eq!(
        correlation.accept_selection(&response_frame, now),
        Err(ProviderCorrelationError::UnknownPrompt)
    );

    let mut replacement = provider_correlation(
        request_id("cfac2219-d065-4602-a26a-26b5bfa33c51"),
        generation(4),
        vec![digest(0x33)],
        vec![ProviderCapability::ProfileQuickPick],
    );
    assert_eq!(
        replacement.accept_selection(&response_frame, now),
        Err(ProviderCorrelationError::RegistrationMismatch)
    );
}

#[test]
fn provider_membership_change_revokes_prompts_and_unoffered_profiles() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let provider_generation = generation(3);
    let now = Instant::now();
    let mut correlation = provider_correlation(
        registration_id,
        provider_generation,
        vec![digest(0x33)],
        vec![ProviderCapability::ProfileQuickPick],
    );
    let second_prompt = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(8),
    ))
    .expect("second prompt");
    correlation
        .track_prompt(&second_prompt, now)
        .expect("tracked");
    let unoffered = ProviderSelectionDecision::new(
        registration_id,
        provider_generation,
        generation(8),
        ProviderDecision::Selected(profile_id("personal")),
    )
    .expect("syntactically valid decision");
    let unoffered_frame =
        ProviderRequestFrame::selection_response(second_prompt.request_id(), unoffered)
            .expect("response frame");
    assert_eq!(
        correlation.accept_selection(&unoffered_frame, now),
        Err(ProviderCorrelationError::ProfileNotOffered)
    );
    assert_eq!(correlation.outstanding_prompt_count(), 1);

    let membership = ProviderRepositoryMembership::new(
        registration_id,
        provider_generation,
        generation(1),
        vec![digest(2)],
    )
    .expect("membership");
    let membership_frame =
        ProviderRequestFrame::control(ProviderRequest::UpdateRepositories(membership))
            .expect("membership frame");
    let revoked = correlation
        .accept_membership(&membership_frame)
        .expect("first membership");
    assert_eq!(revoked, vec![second_prompt.request_id()]);
    assert_eq!(correlation.outstanding_prompt_count(), 0);
    assert_eq!(
        correlation.accept_membership(&membership_frame),
        Err(ProviderCorrelationError::StaleMembership)
    );
}

#[test]
fn provider_prompt_lifecycle_releases_timeout_failure_and_disconnect_waiters() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let provider_generation = generation(3);
    let now = Instant::now();
    let mut correlation = provider_correlation(
        registration_id,
        provider_generation,
        vec![digest(0x33)],
        vec![ProviderCapability::ProfileQuickPick],
    );

    let expired_prompt = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(1),
    ))
    .expect("expired prompt");
    correlation
        .track_prompt(&expired_prompt, now)
        .expect("track expiring prompt");
    let late_decision = ProviderSelectionDecision::new(
        registration_id,
        provider_generation,
        generation(1),
        ProviderDecision::Cancelled,
    )
    .expect("late decision");
    let late_frame =
        ProviderRequestFrame::selection_response(expired_prompt.request_id(), late_decision)
            .expect("late response frame");
    assert_eq!(
        correlation.accept_selection(&late_frame, now + Duration::from_secs(30)),
        Err(ProviderCorrelationError::PromptExpired)
    );
    assert_eq!(correlation.outstanding_prompt_count(), 0);

    let pruned_prompt = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(2),
    ))
    .expect("pruned prompt");
    correlation
        .track_prompt(&pruned_prompt, now)
        .expect("track pruned prompt");
    let replacement_prompt = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(3),
    ))
    .expect("replacement prompt");
    assert_eq!(
        correlation
            .track_prompt(&replacement_prompt, now + Duration::from_secs(31))
            .expect("expired capacity is reclaimed"),
        vec![pruned_prompt.request_id()]
    );
    assert!(correlation.abandon_prompt(replacement_prompt.request_id()));
    assert!(!correlation.abandon_prompt(replacement_prompt.request_id()));

    let disconnect_prompt = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(4),
    ))
    .expect("disconnect prompt");
    correlation
        .track_prompt(&disconnect_prompt, now)
        .expect("track disconnect prompt");
    assert_eq!(
        correlation.disconnect(),
        vec![disconnect_prompt.request_id()]
    );
}

#[test]
fn provider_capabilities_and_repository_membership_are_enforced() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let provider_generation = generation(3);
    let correlation = provider_correlation(
        registration_id,
        provider_generation,
        vec![digest(0x22)],
        vec![ProviderCapability::ProfileQuickPick],
    );
    let status = ProviderStatusSnapshot::new(registration_id, provider_generation, Vec::new())
        .expect("empty status");
    let status_frame = ProviderResponseFrame::status_snapshot(status).expect("status frame");
    assert_eq!(
        correlation.validate_status(&status_frame),
        Err(ProviderCorrelationError::CapabilityNotNegotiated)
    );

    let prompt_frame = ProviderResponseFrame::selection_prompt(prompt(
        registration_id,
        provider_generation,
        generation(1),
    ))
    .expect("prompt frame");
    let mut correlation = correlation;
    assert_eq!(
        correlation.track_prompt(&prompt_frame, Instant::now()),
        Err(ProviderCorrelationError::RepositoryNotRegistered)
    );
}

#[test]
fn scoped_status_keeps_scm_terminals_and_tasks_independent() {
    let registration_id = request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac");
    let provider_generation = generation(3);
    let entries = vec![
        ProviderStatusEntry::new(
            scope(SelectionScopePresentation::IdeWindow, 1, "SCM"),
            repository(9, "gus"),
            Some(profile("work", "Work")),
            ProtectionStatus::Verified,
        )
        .expect("SCM status"),
        ProviderStatusEntry::new(
            scope(SelectionScopePresentation::Terminal, 2, "Terminal A"),
            repository(9, "gus"),
            Some(profile("personal", "Personal")),
            ProtectionStatus::Verified,
        )
        .expect("terminal status"),
        ProviderStatusEntry::new(
            scope(SelectionScopePresentation::IdeTask, 3, "Task"),
            repository(9, "gus"),
            None,
            ProtectionStatus::Unverified,
        )
        .expect("task status"),
    ];
    let snapshot = ProviderStatusSnapshot::new(registration_id, provider_generation, entries)
        .expect("snapshot");
    let frame = ProviderResponseFrame::status_snapshot(snapshot).expect("status frame");
    let correlation = provider_correlation(
        registration_id,
        provider_generation,
        vec![digest(9)],
        vec![
            ProviderCapability::ProfileQuickPick,
            ProviderCapability::Status,
        ],
    );
    correlation.validate_status(&frame).expect("bound status");
    let BrokerProviderMessage::StatusSnapshot(snapshot) = frame.message() else {
        panic!("expected status snapshot");
    };
    assert_eq!(snapshot.entries().len(), 3);
    assert_ne!(
        snapshot.entries()[0].scope().opaque_id(),
        snapshot.entries()[1].scope().opaque_id()
    );
}

#[test]
fn decoded_values_are_readable_without_reserializing_and_debug_is_redacted() {
    let registration = ProviderRegistrationRequest::new(
        ProviderKind::Vscode,
        "sensitive-window-id".into(),
        digest(1),
        vec![digest(2)],
        vec![
            ProviderCapability::ProfileQuickPick,
            ProviderCapability::Status,
        ],
    )
    .expect("registration");
    assert_eq!(registration.kind(), ProviderKind::Vscode);
    assert_eq!(registration.editor_session_id(), "sensitive-window-id");
    assert_eq!(registration.host_instance(), digest(1));
    assert_eq!(registration.repositories(), &[digest(2)]);
    assert!(
        registration
            .capabilities()
            .contains(&ProviderCapability::Status)
    );
    assert!(!format!("{registration:?}").contains("sensitive-window-id"));

    let accepted = RegistrationAccepted::new(
        request_id("43d84d56-2cc8-41d0-a3b0-1146cb337eac"),
        generation(3),
        15_000,
    )
    .expect("accepted");
    assert_eq!(accepted.provider_generation(), generation(3));
    assert_eq!(accepted.heartbeat_interval_millis(), 15_000);

    let sensitive_profile = profile_id("sensitive-user");
    let resolved =
        gus_ipc::ResolvedSelection::new(sensitive_profile.clone(), generation(1), generation(2))
            .expect("resolved selection");
    let status =
        gus_ipc::SelectionStatus::new(digest(3), Some(sensitive_profile.clone()), generation(2))
            .expect("selection status");
    let decision = ProviderDecision::Selected(sensitive_profile);
    assert!(!format!("{resolved:?}").contains("sensitive-user"));
    assert!(!format!("{status:?}").contains("sensitive-user"));
    assert!(!format!("{decision:?}").contains("sensitive-user"));
}

#[test]
fn presentation_text_rejects_line_break_and_default_ignorable_spoofing() {
    for forbidden in ['\u{00ad}', '\u{180e}', '\u{2028}', '\u{2029}'] {
        let display_name = format!("Work{forbidden}Profile");
        assert_eq!(
            ProfilePresentation::new(profile_id("work"), display_name, None),
            Err(gus_ipc::ProtocolError::InvalidField {
                field: "profile.display_name"
            })
        );
    }
}

#[test]
fn unsupported_version_is_reported_before_decoding_its_message_schema() {
    let future = br#"{"protocol_version":2,"message_family":"shim_request","request_id":"10000000-0000-4000-8000-000000000001","message":{"type":"future_v2","body":{"unknown":true}}}"#;
    assert_eq!(
        decode_shim_request(&record(future)),
        Err(gus_ipc::ProtocolError::UnsupportedVersion { received: 2 })
    );
}

#[test]
fn rust_consumes_the_complete_cross_language_conformance_corpus() {
    let corpus: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/conformance-v1.json"))
            .expect("valid corpus JSON");
    let valid = corpus["valid"].as_array().expect("valid case array");
    assert_eq!(valid.len(), 20);
    for case in valid {
        let direction = case["direction"].as_str().expect("direction");
        let payload = serde_json::to_vec(&case["payload"]).expect("payload JSON");
        let frame = record(&payload);
        let accepted = match direction {
            "shim_request" => decode_shim_request(&frame).is_ok(),
            "shim_response" => decode_shim_response(&frame).is_ok(),
            "provider_request" => decode_provider_request(&frame).is_ok(),
            "provider_response" => decode_provider_response(&frame).is_ok(),
            other => panic!("unknown direction {other}"),
        };
        assert!(
            accepted,
            "Rust rejected valid {direction}: {}",
            case["payload"]
        );

        let mut message_unknown = case["payload"].clone();
        message_unknown["message"]["unexpected"] = serde_json::json!(true);
        let mutated = record(&serde_json::to_vec(&message_unknown).expect("mutation JSON"));
        let accepted = match direction {
            "shim_request" => decode_shim_request(&mutated).is_ok(),
            "shim_response" => decode_shim_response(&mutated).is_ok(),
            "provider_request" => decode_provider_request(&mutated).is_ok(),
            "provider_response" => decode_provider_response(&mutated).is_ok(),
            _ => unreachable!(),
        };
        assert!(!accepted, "message-level unknown field was accepted");

        let mut body_unknown = case["payload"].clone();
        if let Some(body) = body_unknown["message"]
            .get_mut("body")
            .and_then(serde_json::Value::as_object_mut)
        {
            body.insert("unexpected".into(), serde_json::json!(true));
            let mutated = record(&serde_json::to_vec(&body_unknown).expect("mutation JSON"));
            let accepted = match direction {
                "shim_request" => decode_shim_request(&mutated).is_ok(),
                "shim_response" => decode_shim_response(&mutated).is_ok(),
                "provider_request" => decode_provider_request(&mutated).is_ok(),
                "provider_response" => decode_provider_response(&mutated).is_ok(),
                _ => unreachable!(),
            };
            assert!(!accepted, "body-level unknown field was accepted");
        }
    }

    let invalid = corpus["invalid"].as_array().expect("invalid case array");
    assert!(invalid.len() >= 7);
    for case in invalid {
        let direction = case["direction"].as_str().expect("direction");
        let payload = serde_json::to_vec(&case["payload"]).expect("payload JSON");
        let frame = record(&payload);
        let accepted = match direction {
            "shim_request" => decode_shim_request(&frame).is_ok(),
            "shim_response" => decode_shim_response(&frame).is_ok(),
            "provider_request" => decode_provider_request(&frame).is_ok(),
            "provider_response" => decode_provider_response(&frame).is_ok(),
            other => panic!("unknown direction {other}"),
        };
        assert!(
            !accepted,
            "Rust accepted invalid {direction}: {}",
            case["payload"]
        );
    }
}

#[test]
fn rust_rejects_the_cross_language_wire_negative_corpus() {
    let cases: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/wire-negative-v1.json"))
            .expect("valid wire-negative corpus JSON");
    let cases = cases.as_array().expect("wire-negative case array");
    assert_eq!(cases.len(), 8);
    for case in cases {
        let direction = case["direction"].as_str().expect("direction");
        let payload = case["payload"].as_str().expect("payload");
        let frame = record(payload.as_bytes());
        let accepted = match direction {
            "shim_request" => decode_shim_request(&frame).is_ok(),
            "shim_response" => decode_shim_response(&frame).is_ok(),
            "provider_request" => decode_provider_request(&frame).is_ok(),
            "provider_response" => decode_provider_response(&frame).is_ok(),
            other => panic!("unknown direction {other}"),
        };
        assert!(
            !accepted,
            "Rust accepted wire-negative case {}",
            case["name"]
        );
    }
}

#[test]
fn every_error_code_matches_the_cross_language_catalog_fixture() {
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(include_bytes!("fixtures/error-contract-v1.json"))
            .expect("valid error catalog fixture");
    assert_eq!(values.len(), 31);
    let mut codes = std::collections::BTreeSet::new();
    for value in values {
        let error: BrokerError = serde_json::from_value(value.clone()).expect("valid error");
        assert!(codes.insert(format!("{:?}", error.code())));
        assert_eq!(
            serde_json::to_value(error).expect("error serializes canonically"),
            value
        );
    }
    assert_eq!(codes.len(), 31);
}
