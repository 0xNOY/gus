use std::ffi::{OsStr, OsString};

use sha2::{Digest, Sha256};

use crate::model::{
    CliBooleanOverride, EndpointRole, HttpPreflightDisposition, IdentityCreationEvidence,
    InvocationContext, Operation, ResolutionError, ResolvedInvocation, SnapshotGenerations,
    Transport,
};

/// One effective Git configuration record in the order returned by the fixed
/// real-Git resolver. Includes and worktree configuration must already have
/// been expanded by Git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfigEntry {
    name: String,
    value: OsString,
}

impl EffectiveConfigEntry {
    #[must_use]
    pub fn new(name: String, value: OsString) -> Self {
        Self { name, value }
    }
}

/// Raw endpoint observation produced while resolving remotes and submodules.
/// It is not policy evidence until [`GitResolver`] binds it to a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointObservation {
    role: EndpointRole,
    transport: Transport,
    identity_digest: [u8; 32],
}

/// Opaque HTTP preflight observation captured by the trusted platform probe.
/// There is deliberately no public constructor: an IPC/config caller cannot
/// assert `HelperCompatible`. Until a platform probe is implemented inside
/// the resolver TCB, HTTP snapshots therefore fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPreflightObservation {
    role: EndpointRole,
    endpoint_identity_digest: [u8; 32],
    disposition: HttpPreflightDisposition,
}

impl HttpPreflightObservation {
    #[cfg(test)]
    const fn from_verified_probe(
        role: EndpointRole,
        endpoint_identity_digest: [u8; 32],
        disposition: HttpPreflightDisposition,
    ) -> Self {
        Self {
            role,
            endpoint_identity_digest,
            disposition,
        }
    }
}

/// Git behavior family for which the resolver's effective-config rules have
/// been verified by executable fixtures. Minor versions are admitted only by
/// an explicit entry here; an unknown version never inherits a nearby rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitSemanticRuleset {
    Git2_39,
    Git2_55,
    Unsupported,
}

/// Credential-helper wire protocol verified for the fixed real Git. This is
/// intentionally separate from identity-creation semantics: a vendor Git may
/// be admitted for legacy credential exchange while identity-free merge proof
/// remains unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCredentialProtocolRuleset {
    LegacySerial,
    Stateful,
    Unsupported,
}

/// One process interaction captured by the exact-build credential probe.
/// Core validates the complete wire transcript; callers cannot select a
/// ruleset or provide its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCredentialProbeAction {
    Capability,
    Get,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCredentialProbeExchange {
    action: GitCredentialProbeAction,
    input: Vec<u8>,
    output: Vec<u8>,
    exit_code: i32,
    started_order: u32,
    finished_order: u32,
}

impl GitCredentialProbeExchange {
    #[must_use]
    pub fn new(
        action: GitCredentialProbeAction,
        input: Vec<u8>,
        output: Vec<u8>,
        exit_code: i32,
        started_order: u32,
        finished_order: u32,
    ) -> Self {
        Self {
            action,
            input,
            output,
            exit_code,
            started_order,
            finished_order,
        }
    }
}

/// Raw, bounded process transcript emitted by the fixed probe harness. The
/// transcript contains no live credential: it uses only the reserved
/// `gus-probe.invalid` endpoint and fixed sentinel material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCredentialProtocolProbeTranscript {
    exchanges: Vec<GitCredentialProbeExchange>,
}

impl GitCredentialProtocolProbeTranscript {
    #[must_use]
    pub fn new(exchanges: Vec<GitCredentialProbeExchange>) -> Self {
        Self { exchanges }
    }
}

/// Sealed receipt for one exact real-Git executable/version observation and
/// its credential-protocol probe transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCredentialProtocolAdmission {
    executable_identity: [u8; 32],
    version_output: String,
    ruleset: GitCredentialProtocolRuleset,
    probe_transcript_digest: [u8; 32],
}

impl GitCredentialProtocolAdmission {
    /// Verifies a probe result and binds it to one exact executable and full
    /// non-lossy `git --version` output.
    ///
    /// # Errors
    ///
    /// Rejects malformed, overlapping, incomplete, or self-contradictory wire
    /// transcripts. The ruleset and transcript digest are derived by core.
    pub fn from_transcript(
        executable_identity: [u8; 32],
        version_output: &str,
        transcript: &GitCredentialProtocolProbeTranscript,
    ) -> Result<Self, ResolutionError> {
        if executable_identity == [0; 32] {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let version_output = validated_version_output(version_output)?;
        let ruleset = validate_credential_probe_transcript(transcript)?;
        let probe_transcript_digest = credential_probe_transcript_digest(transcript);
        Ok(Self {
            executable_identity,
            version_output: version_output.to_owned(),
            ruleset,
            probe_transcript_digest,
        })
    }
}

const PROBE_PROTOCOL: &[u8] = b"https";
const PROBE_HOST: &[u8] = b"gus-probe.invalid";
const PROBE_STATE: &[u8] = b"gus-probe-state-v1";
const MAX_PROBE_TRANSCRIPT_BYTES: usize = 1024 * 1024;
type CredentialAttributes<'a> = Vec<(&'a [u8], &'a [u8])>;

fn validate_credential_probe_transcript(
    transcript: &GitCredentialProtocolProbeTranscript,
) -> Result<GitCredentialProtocolRuleset, ResolutionError> {
    let [capability, first, second] = transcript.exchanges.as_slice() else {
        return Err(ResolutionError::InvalidSnapshot);
    };
    let total_bytes = transcript
        .exchanges
        .iter()
        .try_fold(0usize, |total, exchange| {
            total
                .checked_add(exchange.input.len())?
                .checked_add(exchange.output.len())
        });
    if total_bytes.is_none_or(|total| total > MAX_PROBE_TRANSCRIPT_BYTES)
        || capability.action != GitCredentialProbeAction::Capability
        || !capability.input.is_empty()
        || first.action != GitCredentialProbeAction::Get
        || second.action != GitCredentialProbeAction::Get
        || first.exit_code != 0
        || second.exit_code != 0
        || !(capability.started_order < capability.finished_order
            && capability.finished_order < first.started_order
            && first.started_order < first.finished_order
            && first.finished_order < second.started_order
            && second.started_order < second.finished_order)
    {
        return Err(ResolutionError::InvalidSnapshot);
    }

    let first_input = parse_credential_attributes(&first.input)?;
    let first_output = parse_credential_attributes(&first.output)?;
    let second_input = parse_credential_attributes(&second.input)?;
    let second_output = parse_credential_attributes(&second.output)?;
    if !is_probe_endpoint(&first_input) || !is_probe_endpoint(&second_input) {
        return Err(ResolutionError::InvalidSnapshot);
    }

    let capability_state = capability.exit_code == 0
        && parse_capability_output(&capability.output)
            .is_some_and(|capabilities| capabilities.iter().any(|value| value == b"state"));
    let first_announces_state = attribute_precedes(
        &first_output,
        (b"capability[]", b"state"),
        (b"state[]", PROBE_STATE),
    );
    let first_input_supports_state = has_attribute(&first_input, b"capability[]", b"state");
    let second_input_supports_state = has_attribute(&second_input, b"capability[]", b"state");
    let first_returns_state = has_attribute(&first_output, b"state[]", PROBE_STATE);
    let second_receives_state = has_attribute(&second_input, b"state[]", PROBE_STATE);
    let first_continues = has_attribute(&first_output, b"continue", b"true");

    if capability_state
        && first_input_supports_state
        && second_input_supports_state
        && attribute_count(&first_input, b"capability[]", b"state") == 1
        && attribute_count(&second_input, b"capability[]", b"state") == 1
        && first_announces_state
        && attribute_count(&first_output, b"capability[]", b"state") == 1
        && first_returns_state
        && attribute_count(&first_output, b"state[]", PROBE_STATE) == 1
        && second_receives_state
        && attribute_count(&second_input, b"state[]", PROBE_STATE) == 1
        && first_continues
        && !has_key(&second_output, b"continue")
    {
        return Ok(GitCredentialProtocolRuleset::Stateful);
    }
    if capability.exit_code != 0
        && !first_input_supports_state
        && !second_input_supports_state
        && !has_key(&first_input, b"state[]")
        && !has_key(&second_input, b"state[]")
        && !has_key(&first_output, b"capability[]")
        && first_returns_state
        && attribute_count(&first_output, b"state[]", PROBE_STATE) == 1
        && !second_receives_state
        && !has_key(&first_output, b"continue")
    {
        return Ok(GitCredentialProtocolRuleset::LegacySerial);
    }
    Err(ResolutionError::InvalidSnapshot)
}

fn parse_credential_attributes(input: &[u8]) -> Result<CredentialAttributes<'_>, ResolutionError> {
    if input.contains(&0) {
        return Err(ResolutionError::InvalidSnapshot);
    }
    let mut attributes = Vec::new();
    let mut terminated = false;
    for line in input.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            terminated = true;
            break;
        }
        if line.len() > u16::MAX as usize {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            return Err(ResolutionError::InvalidSnapshot);
        };
        if separator == 0 {
            return Err(ResolutionError::InvalidSnapshot);
        }
        attributes.push((&line[..separator], &line[separator + 1..]));
    }
    if terminated {
        let terminator = input
            .windows(2)
            .position(|window| window == b"\n\n")
            .map_or(input.len(), |index| index + 2);
        if input[terminator..]
            .iter()
            .any(|byte| !matches!(*byte, b'\n' | b'\r'))
        {
            return Err(ResolutionError::InvalidSnapshot);
        }
    }
    Ok(attributes)
}

fn parse_capability_output(input: &[u8]) -> Option<Vec<&[u8]>> {
    if input.contains(&0) {
        return None;
    }
    let mut lines = input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    if lines.next()? != b"version 0" {
        return None;
    }
    let mut capabilities = Vec::new();
    for line in lines {
        if line.len() > u16::MAX as usize {
            return None;
        }
        if let Some(value) = line.strip_prefix(b"capability ") {
            capabilities.push(value);
        }
    }
    Some(capabilities)
}

fn is_probe_endpoint(attributes: &[(&[u8], &[u8])]) -> bool {
    attribute_count(attributes, b"protocol", PROBE_PROTOCOL) == 1
        && attribute_count(attributes, b"host", PROBE_HOST) == 1
        && attributes
            .iter()
            .filter(|(key, _)| *key == b"protocol" || *key == b"host")
            .count()
            == 2
        && !has_key(attributes, b"url")
}

fn has_attribute(attributes: &[(&[u8], &[u8])], key: &[u8], value: &[u8]) -> bool {
    attributes
        .iter()
        .any(|(observed_key, observed_value)| *observed_key == key && *observed_value == value)
}

fn has_key(attributes: &[(&[u8], &[u8])], key: &[u8]) -> bool {
    attributes
        .iter()
        .any(|(observed_key, _)| *observed_key == key)
}

fn attribute_count(attributes: &[(&[u8], &[u8])], key: &[u8], value: &[u8]) -> usize {
    attributes
        .iter()
        .filter(|(observed_key, observed_value)| *observed_key == key && *observed_value == value)
        .count()
}

fn attribute_precedes(
    attributes: &[(&[u8], &[u8])],
    first: (&[u8], &[u8]),
    second: (&[u8], &[u8]),
) -> bool {
    let first_index = attributes.iter().position(|value| *value == first);
    let second_index = attributes.iter().position(|value| *value == second);
    matches!((first_index, second_index), (Some(first), Some(second)) if first < second)
}

fn credential_probe_transcript_digest(
    transcript: &GitCredentialProtocolProbeTranscript,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gus.git-credential-probe-transcript.v1\0");
    digest.update((transcript.exchanges.len() as u64).to_le_bytes());
    for exchange in &transcript.exchanges {
        digest.update([match exchange.action {
            GitCredentialProbeAction::Capability => 1,
            GitCredentialProbeAction::Get => 2,
        }]);
        digest.update(exchange.exit_code.to_le_bytes());
        digest.update(exchange.started_order.to_le_bytes());
        digest.update(exchange.finished_order.to_le_bytes());
        digest.update((exchange.input.len() as u64).to_le_bytes());
        digest.update(&exchange.input);
        digest.update((exchange.output.len() as u64).to_le_bytes());
        digest.update(&exchange.output);
    }
    digest.finalize().into()
}

/// Identity and semantic version of the fixed real Git selected by the
/// platform resolver. The digest binds proofs to both the executable identity
/// and the complete, non-lossy `git --version` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGitSemantics {
    executable_identity: [u8; 32],
    version_output: String,
    ruleset: GitSemanticRuleset,
    credential_ruleset: GitCredentialProtocolRuleset,
    digest: [u8; 32],
}

impl VerifiedGitSemantics {
    /// Creates semantics from a version observation made through the same
    /// verified executable handle represented by `executable_identity`.
    ///
    /// # Errors
    ///
    /// Rejects a missing executable identity or malformed Git version output.
    pub fn from_version_output(
        executable_identity: [u8; 32],
        version_output: &str,
    ) -> Result<Self, ResolutionError> {
        if executable_identity == [0; 32] {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let version_output = validated_version_output(version_output)?;
        let version = version_output
            .strip_prefix("git version ")
            .and_then(|remainder| remainder.split_ascii_whitespace().next())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let mut components = version.split('.');
        let major = components
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let minor = components
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let patch = components
            .next()
            .and_then(|value| value.split('-').next())
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(ResolutionError::InvalidSnapshot)?;
        let _ = patch;
        let ruleset = match (major, minor) {
            (2, 39) => GitSemanticRuleset::Git2_39,
            (2, 55) => GitSemanticRuleset::Git2_55,
            _ => GitSemanticRuleset::Unsupported,
        };
        let credential_ruleset = GitCredentialProtocolRuleset::Unsupported;
        let mut digest = Sha256::new();
        digest.update(b"gus.git-semantics.v1\0");
        digest.update(executable_identity);
        digest.update((version_output.len() as u64).to_le_bytes());
        digest.update(version_output.as_bytes());
        digest.update([match ruleset {
            GitSemanticRuleset::Git2_39 => 1,
            GitSemanticRuleset::Git2_55 => 2,
            GitSemanticRuleset::Unsupported => 0,
        }]);
        digest.update([match credential_ruleset {
            GitCredentialProtocolRuleset::LegacySerial => 1,
            GitCredentialProtocolRuleset::Stateful => 2,
            GitCredentialProtocolRuleset::Unsupported => 0,
        }]);
        Ok(Self {
            executable_identity,
            version_output: version_output.to_owned(),
            ruleset,
            credential_ruleset,
            digest: digest.finalize().into(),
        })
    }

    /// Applies a credential-protocol admission only when it was produced for
    /// this exact executable and complete version observation.
    ///
    /// # Errors
    ///
    /// Rejects a receipt from any other executable or build.
    pub fn with_credential_protocol_admission(
        mut self,
        admission: &GitCredentialProtocolAdmission,
    ) -> Result<Self, ResolutionError> {
        if self.executable_identity != admission.executable_identity
            || self.version_output != admission.version_output
        {
            return Err(ResolutionError::BindingMismatch);
        }
        self.credential_ruleset = admission.ruleset;
        let mut digest = Sha256::new();
        digest.update(b"gus.git-semantics.credential-admission.v1\0");
        digest.update(self.digest);
        digest.update([match admission.ruleset {
            GitCredentialProtocolRuleset::LegacySerial => 1,
            GitCredentialProtocolRuleset::Stateful => 2,
            GitCredentialProtocolRuleset::Unsupported => 0,
        }]);
        digest.update(admission.probe_transcript_digest);
        self.digest = digest.finalize().into();
        Ok(self)
    }

    #[must_use]
    pub const fn executable_identity(&self) -> [u8; 32] {
        self.executable_identity
    }

    #[must_use]
    pub fn version_output(&self) -> &str {
        &self.version_output
    }

    #[must_use]
    pub const fn ruleset(&self) -> GitSemanticRuleset {
        self.ruleset
    }

    #[must_use]
    pub const fn credential_ruleset(&self) -> GitCredentialProtocolRuleset {
        self.credential_ruleset
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    const fn supports_identity_proofs(&self) -> bool {
        !matches!(self.ruleset, GitSemanticRuleset::Unsupported)
    }
}

fn validated_version_output(version_output: &str) -> Result<&str, ResolutionError> {
    let version_output = version_output.trim();
    if version_output.is_empty()
        || version_output.chars().any(char::is_control)
        || !version_output.starts_with("git version ")
    {
        return Err(ResolutionError::InvalidSnapshot);
    }
    Ok(version_output)
}

impl EndpointObservation {
    #[must_use]
    pub const fn new(role: EndpointRole, transport: Transport, identity_digest: [u8; 32]) -> Self {
        Self {
            role,
            transport,
            identity_digest,
        }
    }
}

/// Inputs captured atomically by the filesystem/config resolver. The config
/// digest is computed here rather than accepted from a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverSnapshot {
    repository_identity: [u8; 32],
    git_semantics: VerifiedGitSemantics,
    head_state_digest: Option<[u8; 32]>,
    generations: SnapshotGenerations,
    current_branch: Option<String>,
    config_entries: Vec<EffectiveConfigEntry>,
    config_snapshot_digest: [u8; 32],
    endpoints: Vec<EndpointObservation>,
    http_preflight: Vec<HttpPreflightObservation>,
}

impl ResolverSnapshot {
    /// Creates a snapshot from raw observations. Identity digests must be
    /// produced from open handles by the platform resolver.
    ///
    /// # Errors
    ///
    /// Rejects zero repository/endpoint identities, which represent missing
    /// observations rather than a valid snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_identity: [u8; 32],
        git_semantics: VerifiedGitSemantics,
        head_state_digest: Option<[u8; 32]>,
        generations: SnapshotGenerations,
        current_branch: Option<String>,
        config_entries: Vec<EffectiveConfigEntry>,
        endpoints: Vec<EndpointObservation>,
        http_preflight: Vec<HttpPreflightObservation>,
    ) -> Result<Self, ResolutionError> {
        if repository_identity == [0; 32]
            || endpoints
                .iter()
                .any(|endpoint| endpoint.identity_digest == [0; 32])
            || http_preflight
                .iter()
                .any(|evidence| evidence.endpoint_identity_digest == [0; 32])
            || !raw_http_preflight_set_matches(&endpoints, &http_preflight)
        {
            return Err(ResolutionError::InvalidSnapshot);
        }
        let configured_disposition = configured_http_preflight(&config_entries);
        let http_preflight = http_preflight
            .into_iter()
            .map(|mut evidence| {
                if let Some(configured) = configured_disposition {
                    evidence.disposition = combine_http_preflight(evidence.disposition, configured);
                }
                evidence
            })
            .collect::<Vec<_>>();
        let config_snapshot_digest =
            digest_config(current_branch.as_deref(), &config_entries, &http_preflight);
        Ok(Self {
            repository_identity,
            git_semantics,
            head_state_digest,
            generations,
            current_branch,
            config_entries,
            config_snapshot_digest,
            endpoints,
            http_preflight,
        })
    }
}

/// Sealed policy-evidence producer. Callers provide raw effective Git records;
/// they cannot directly construct an identity-free proof.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitResolver;

impl GitResolver {
    /// Binds a parsed invocation and a complete snapshot, derives aggregate
    /// identity-creation evidence, and validates endpoint completeness.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionError`] for cross-snapshot evidence, missing HEAD
    /// state required by an identity-free integration, or incompatible
    /// endpoint roles/counts.
    pub fn resolve(
        self,
        invocation: InvocationContext,
        snapshot: ResolverSnapshot,
    ) -> Result<ResolvedInvocation, ResolutionError> {
        let config = EffectiveFacts::from_snapshot(&snapshot, invocation.operation());
        let request = invocation.begin_resolution(
            snapshot.repository_identity,
            snapshot.git_semantics.digest(),
            snapshot.config_snapshot_digest,
            snapshot.head_state_digest,
            snapshot.generations,
        );
        let endpoints = snapshot
            .endpoints
            .into_iter()
            .map(|endpoint| {
                request.bind_endpoint(endpoint.role, endpoint.transport, endpoint.identity_digest)
            })
            .collect();
        let http_preflight = snapshot
            .http_preflight
            .into_iter()
            .map(|evidence| {
                request.bind_http_preflight(
                    evidence.role,
                    evidence.endpoint_identity_digest,
                    evidence.disposition,
                )
            })
            .collect();
        let effective_config = request.bind_effective_config(
            config.merge_ff_only,
            config.pull_ff_only,
            config.lightweight_tag,
        );
        request.resolve(endpoints, effective_config, http_preflight)
    }
}

#[derive(Debug, Clone, Copy)]
struct EffectiveFacts {
    merge_ff_only: IdentityCreationEvidence,
    pull_ff_only: IdentityCreationEvidence,
    lightweight_tag: IdentityCreationEvidence,
}

impl EffectiveFacts {
    fn from_snapshot(snapshot: &ResolverSnapshot, operation: Operation) -> Self {
        if !snapshot.git_semantics.supports_identity_proofs() {
            return Self {
                merge_ff_only: IdentityCreationEvidence::MayCreateOrUnresolved,
                pull_ff_only: IdentityCreationEvidence::MayCreateOrUnresolved,
                lightweight_tag: IdentityCreationEvidence::MayCreateOrUnresolved,
            };
        }
        let config = ConfigView::new(snapshot);
        let merge_options_safe = config.branch_merge_options_are_identity_free();
        let merge_autostash = config.boolean("merge.autostash");
        let merge_ff_only = evidence(merge_options_safe && merge_autostash.is_disabled());

        let (cli_rebase, cli_autostash) = match operation {
            Operation::Pull {
                rebase, autostash, ..
            } => (rebase, autostash),
            _ => (
                CliBooleanOverride::Unspecified,
                CliBooleanOverride::Unspecified,
            ),
        };
        let rebase = config.pull_uses_rebase(cli_rebase);
        let configured_pull_autostash = match snapshot.git_semantics.ruleset() {
            // Git 2.39 has no pull.autoStash key. Treating an ignored false
            // value as authoritative could hide merge.autoStash=true.
            GitSemanticRuleset::Git2_39 => ParsedBoolean::Unset,
            GitSemanticRuleset::Git2_55 => config.boolean("pull.autostash"),
            GitSemanticRuleset::Unsupported => unreachable!("handled above"),
        };
        let effective_pull_autostash = if cli_autostash != CliBooleanOverride::Unspecified {
            ParsedBoolean::from_cli(cli_autostash)
        } else if !configured_pull_autostash.is_unset() {
            configured_pull_autostash
        } else if rebase == ParsedBoolean::Enabled {
            config.boolean("rebase.autostash")
        } else if rebase == ParsedBoolean::Disabled {
            merge_autostash
        } else {
            ParsedBoolean::Invalid
        };
        let pull_options_safe = if rebase == ParsedBoolean::Enabled {
            true
        } else if rebase == ParsedBoolean::Disabled {
            merge_options_safe
        } else {
            false
        };
        let pull_ff_only = evidence(pull_options_safe && effective_pull_autostash.is_disabled());

        let lightweight_tag = evidence(config.boolean("tag.gpgsign").is_disabled());
        Self {
            merge_ff_only,
            pull_ff_only,
            lightweight_tag,
        }
    }
}

const fn evidence(identity_free: bool) -> IdentityCreationEvidence {
    if identity_free {
        IdentityCreationEvidence::IdentityFreeProven
    } else {
        IdentityCreationEvidence::MayCreateOrUnresolved
    }
}

struct ConfigView<'a> {
    branch: Option<&'a str>,
    entries: &'a [EffectiveConfigEntry],
}

impl<'a> ConfigView<'a> {
    fn new(snapshot: &'a ResolverSnapshot) -> Self {
        Self {
            branch: snapshot.current_branch.as_deref(),
            entries: &snapshot.config_entries,
        }
    }

    fn values(&self, name: &str) -> impl DoubleEndedIterator<Item = &OsStr> {
        self.entries
            .iter()
            .filter(move |entry| entry.name.eq_ignore_ascii_case(name))
            .map(|entry| entry.value.as_os_str())
    }

    fn boolean(&self, name: &str) -> ParsedBoolean {
        self.values(name)
            .next_back()
            .map_or(ParsedBoolean::Unset, parse_boolean)
    }

    fn pull_uses_rebase(&self, cli: CliBooleanOverride) -> ParsedBoolean {
        if cli != CliBooleanOverride::Unspecified {
            return ParsedBoolean::from_cli(cli);
        }
        if self.branch.is_some() {
            let branch_value = self.branch_boolean("rebase");
            if !branch_value.is_unset() {
                return branch_value;
            }
        }
        self.boolean("pull.rebase")
            .with_unset_default(ParsedBoolean::Disabled)
    }

    fn branch_merge_options_are_identity_free(&self) -> bool {
        if self.branch.is_none() {
            return false;
        }
        self.branch_values("mergeoptions").all(safe_merge_options)
    }

    fn branch_boolean(&self, key: &str) -> ParsedBoolean {
        self.branch_values(key)
            .next_back()
            .map_or(ParsedBoolean::Unset, parse_boolean)
    }

    fn branch_values(&self, key: &str) -> impl DoubleEndedIterator<Item = &OsStr> {
        let branch = self.branch;
        self.entries.iter().filter_map(move |entry| {
            let (section, remainder) = entry.name.split_once('.')?;
            let (subsection, entry_key) = remainder.rsplit_once('.')?;
            (section.eq_ignore_ascii_case("branch")
                && branch == Some(subsection)
                && entry_key.eq_ignore_ascii_case(key))
            .then_some(entry.value.as_os_str())
        })
    }
}

fn safe_merge_options(value: &OsStr) -> bool {
    let Some(value) = value.to_str() else {
        return false;
    };
    if value.trim().is_empty() {
        return false;
    }
    value.split_ascii_whitespace().all(|option| {
        matches!(
            option,
            "--ff-only"
                | "--no-autostash"
                | "--stat"
                | "--no-stat"
                | "--compact-summary"
                | "--no-compact-summary"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v"
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedBoolean {
    Unset,
    Enabled,
    Disabled,
    Invalid,
}

impl ParsedBoolean {
    const fn from_cli(value: CliBooleanOverride) -> Self {
        match value {
            CliBooleanOverride::Unspecified => Self::Unset,
            CliBooleanOverride::Enabled => Self::Enabled,
            CliBooleanOverride::Disabled => Self::Disabled,
        }
    }

    const fn is_unset(self) -> bool {
        matches!(self, Self::Unset)
    }

    const fn is_disabled(self) -> bool {
        matches!(self, Self::Unset | Self::Disabled)
    }

    const fn with_unset_default(self, default: Self) -> Self {
        if self.is_unset() { default } else { self }
    }
}

fn parse_boolean(value: &OsStr) -> ParsedBoolean {
    let Some(value) = value.to_str() else {
        return ParsedBoolean::Invalid;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "true" | "yes" | "on" | "1" | "merges" | "interactive" => ParsedBoolean::Enabled,
        "false" | "no" | "off" | "0" => ParsedBoolean::Disabled,
        _ => ParsedBoolean::Invalid,
    }
}

fn raw_http_preflight_set_matches(
    endpoints: &[EndpointObservation],
    preflight: &[HttpPreflightObservation],
) -> bool {
    let http_endpoints = endpoints
        .iter()
        .filter(|endpoint| endpoint.transport == Transport::Http)
        .collect::<Vec<_>>();
    if http_endpoints.len() != preflight.len() {
        return false;
    }
    let mut matched = vec![false; preflight.len()];
    for endpoint in http_endpoints {
        let Some((index, _)) = preflight.iter().enumerate().find(|(index, evidence)| {
            !matched[*index]
                && evidence.role == endpoint.role
                && evidence.endpoint_identity_digest == endpoint.identity_digest
        }) else {
            return false;
        };
        matched[index] = true;
    }
    matched.into_iter().all(|value| value)
}

fn configured_http_preflight(entries: &[EffectiveConfigEntry]) -> Option<HttpPreflightDisposition> {
    let mut disposition = None;
    for entry in entries
        .iter()
        .filter(|entry| !entry.value.as_os_str().is_empty())
    {
        let name = entry.name.to_ascii_lowercase();
        let proxy = name == "http.proxy"
            || name == "http.proxyauthmethod"
            || (name.starts_with("http.") && config_key_suffix_is(&name, "proxy"))
            || (name.starts_with("remote.") && config_key_suffix_is(&name, "proxy"))
            || name.starts_with("http.proxyssl");
        let client_identity = name == "http.sslcert"
            || name == "http.sslkey"
            || (name.starts_with("http.")
                && (config_key_suffix_is(&name, "sslcert")
                    || config_key_suffix_is(&name, "sslkey")));
        if proxy {
            return Some(HttpPreflightDisposition::ProxyTransport);
        }
        if client_identity {
            disposition = Some(HttpPreflightDisposition::PreHandshakeIdentity);
        }
    }
    disposition
}

fn config_key_suffix_is(name: &str, expected: &str) -> bool {
    name.rsplit('.').next() == Some(expected)
}

const fn combine_http_preflight(
    observed: HttpPreflightDisposition,
    configured: HttpPreflightDisposition,
) -> HttpPreflightDisposition {
    match (observed, configured) {
        (HttpPreflightDisposition::ProxyTransport, _)
        | (_, HttpPreflightDisposition::ProxyTransport) => HttpPreflightDisposition::ProxyTransport,
        (HttpPreflightDisposition::PreHandshakeIdentity, _)
        | (_, HttpPreflightDisposition::PreHandshakeIdentity) => {
            HttpPreflightDisposition::PreHandshakeIdentity
        }
        (HttpPreflightDisposition::Unresolved, _) | (_, HttpPreflightDisposition::Unresolved) => {
            HttpPreflightDisposition::Unresolved
        }
        _ => HttpPreflightDisposition::HelperCompatible,
    }
}

fn digest_config(
    branch: Option<&str>,
    entries: &[EffectiveConfigEntry],
    http_preflight: &[HttpPreflightObservation],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gus.effective-config.v1\0");
    if let Some(branch) = branch {
        digest.update((branch.len() as u64).to_le_bytes());
        digest.update(branch.as_bytes());
    } else {
        digest.update(0_u64.to_le_bytes());
    }
    for entry in entries {
        digest.update((entry.name.len() as u64).to_le_bytes());
        digest.update(entry.name.as_bytes());
        let value = entry.value.as_os_str().as_encoded_bytes();
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    for evidence in http_preflight {
        digest.update([match evidence.role {
            EndpointRole::Fetch => 1,
            EndpointRole::Push => 2,
            EndpointRole::Submodule => 3,
        }]);
        digest.update(evidence.endpoint_identity_digest);
        digest.update([match evidence.disposition {
            HttpPreflightDisposition::HelperCompatible => 1,
            HttpPreflightDisposition::PreHandshakeIdentity => 2,
            HttpPreflightDisposition::ProxyTransport => 3,
            HttpPreflightDisposition::Unresolved => 0,
        }]);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileRequirement, RequirementReason};

    fn generations() -> SnapshotGenerations {
        SnapshotGenerations::new(1, 1).expect("valid generations")
    }

    fn entry(name: &str, value: &str) -> EffectiveConfigEntry {
        EffectiveConfigEntry::new(name.to_owned(), value.into())
    }

    fn semantics(version: &str) -> VerifiedGitSemantics {
        VerifiedGitSemantics::from_version_output([8; 32], version)
            .expect("valid fixture Git semantics")
    }

    fn credential_probe(stateful: bool) -> GitCredentialProtocolProbeTranscript {
        let (capability_output, capability_exit, first_input, first_output, second_input) =
            if stateful {
                (
                    b"version 0\ncapability authtype\ncapability state\n".to_vec(),
                    0,
                    b"capability[]=state\nprotocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                    b"capability[]=state\nstate[]=gus-probe-state-v1\ncontinue=true\nusername=probe\npassword=probe\n\n".to_vec(),
                    b"capability[]=state\nprotocol=https\nhost=gus-probe.invalid\nstate[]=gus-probe-state-v1\n\n".to_vec(),
                )
            } else {
                (
                    b"git: 'credential capability' is not supported\n".to_vec(),
                    129,
                    b"protocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                    b"state[]=gus-probe-state-v1\nusername=probe\npassword=probe\n\n".to_vec(),
                    b"protocol=https\nhost=gus-probe.invalid\n\n".to_vec(),
                )
            };
        GitCredentialProtocolProbeTranscript::new(vec![
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Capability,
                Vec::new(),
                capability_output,
                capability_exit,
                1,
                2,
            ),
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Get,
                first_input,
                first_output,
                0,
                3,
                4,
            ),
            GitCredentialProbeExchange::new(
                GitCredentialProbeAction::Get,
                second_input,
                b"username=probe\npassword=probe\n\n".to_vec(),
                0,
                5,
                6,
            ),
        ])
    }

    fn resolve_pull_invocation(
        version: &str,
        args: &[&str],
        branch: Option<&str>,
        head: Option<[u8; 32]>,
        entries: Vec<EffectiveConfigEntry>,
    ) -> ProfileRequirement {
        let snapshot = ResolverSnapshot::new(
            [1; 32],
            semantics(version),
            head,
            generations(),
            branch.map(str::to_owned),
            entries,
            vec![EndpointObservation::new(
                EndpointRole::Fetch,
                Transport::Local,
                [2; 32],
            )],
            Vec::new(),
        )
        .expect("valid snapshot");
        GitResolver
            .resolve(InvocationContext::parse(args), snapshot)
            .expect("valid resolution")
            .profile_requirement()
    }

    fn resolve_pull(
        branch: Option<&str>,
        head: Option<[u8; 32]>,
        entries: Vec<EffectiveConfigEntry>,
    ) -> ProfileRequirement {
        resolve_pull_invocation(
            "git version 2.55.0",
            &["pull", "--ff-only"],
            branch,
            head,
            entries,
        )
    }

    #[test]
    fn branch_subsection_matching_is_case_sensitive() {
        let requirement = resolve_pull(
            Some("foo"),
            Some([3; 32]),
            vec![
                entry("branch.Foo.rebase", "true"),
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "true"),
                entry("rebase.autoStash", "false"),
            ],
        );
        assert_eq!(
            requirement,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn detached_head_and_empty_merge_options_never_produce_identity_free_proof() {
        let detached = resolve_pull(
            None,
            Some([3; 32]),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
            ],
        );
        assert_eq!(
            detached,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );

        let empty_options = resolve_pull(
            Some("main"),
            Some([3; 32]),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
                entry("branch.main.mergeOptions", ""),
            ],
        );
        assert_eq!(
            empty_options,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn identity_proofs_are_available_only_for_explicit_git_rulesets() {
        for version in ["git version 2.39.5", "git version 2.55.0.windows.1"] {
            let semantics = semantics(version);
            assert_ne!(semantics.ruleset(), GitSemanticRuleset::Unsupported);
            let snapshot = ResolverSnapshot::new(
                [1; 32],
                semantics,
                Some([3; 32]),
                generations(),
                Some("main".to_owned()),
                vec![
                    entry("pull.rebase", "false"),
                    entry("merge.autoStash", "false"),
                ],
                vec![EndpointObservation::new(
                    EndpointRole::Fetch,
                    Transport::Local,
                    [2; 32],
                )],
                Vec::new(),
            )
            .expect("valid supported snapshot");
            let requirement = GitResolver
                .resolve(InvocationContext::parse(["pull", "--ff-only"]), snapshot)
                .expect("valid resolution")
                .profile_requirement();
            assert_eq!(requirement, ProfileRequirement::NotRequired, "{version}");
        }

        let unsupported = ResolverSnapshot::new(
            [1; 32],
            semantics("git version 2.54.3"),
            Some([3; 32]),
            generations(),
            Some("main".to_owned()),
            vec![
                entry("pull.rebase", "false"),
                entry("merge.autoStash", "false"),
            ],
            vec![EndpointObservation::new(
                EndpointRole::Fetch,
                Transport::Local,
                [2; 32],
            )],
            Vec::new(),
        )
        .expect("unsupported versions still form conservative snapshots");
        let requirement = GitResolver
            .resolve(InvocationContext::parse(["pull", "--ff-only"]), unsupported)
            .expect("unsupported semantics fail closed in policy")
            .profile_requirement();
        assert_eq!(
            requirement,
            ProfileRequirement::Required(RequirementReason::AuthorIdentity)
        );
    }

    #[test]
    fn pull_autostash_precedence_is_ruleset_specific() {
        let entries = || {
            vec![
                entry("pull.rebase", "false"),
                entry("pull.autoStash", "false"),
                entry("merge.autoStash", "true"),
            ]
        };
        assert_eq!(
            resolve_pull_invocation(
                "git version 2.39.5",
                &["pull", "--ff-only"],
                Some("main"),
                Some([3; 32]),
                entries(),
            ),
            ProfileRequirement::Required(RequirementReason::AuthorIdentity),
            "Git 2.39 ignores pull.autoStash and inherits merge.autoStash"
        );
        assert_eq!(
            resolve_pull_invocation(
                "git version 2.55.0",
                &["pull", "--ff-only"],
                Some("main"),
                Some([3; 32]),
                entries(),
            ),
            ProfileRequirement::NotRequired,
            "Git 2.55 pull.autoStash overrides merge.autoStash"
        );
    }

    #[test]
    fn pull_cli_rebase_and_autostash_override_config_for_every_ruleset() {
        let entries = || {
            vec![
                entry("pull.rebase", "true"),
                entry("rebase.autoStash", "false"),
                entry("merge.autoStash", "true"),
            ]
        };
        for version in ["git version 2.39.5", "git version 2.55.0"] {
            assert_eq!(
                resolve_pull_invocation(
                    version,
                    &["pull", "--ff-only", "--no-rebase"],
                    Some("main"),
                    Some([3; 32]),
                    entries(),
                ),
                ProfileRequirement::Required(RequirementReason::AuthorIdentity),
                "--no-rebase selects merge.autoStash for {version}"
            );
            assert_eq!(
                resolve_pull_invocation(
                    version,
                    &["pull", "--ff-only", "--no-rebase", "--no-autostash",],
                    Some("main"),
                    Some([3; 32]),
                    entries(),
                ),
                ProfileRequirement::NotRequired,
                "--no-autostash overrides merge.autoStash for {version}"
            );
        }
    }

    #[test]
    fn semantics_digest_changes_with_executable_or_version() {
        let base = semantics("git version 2.55.0");
        let other_version = semantics("git version 2.55.1");
        let other_executable =
            VerifiedGitSemantics::from_version_output([9; 32], "git version 2.55.0")
                .expect("valid fixture Git semantics");
        assert_ne!(base.digest(), other_version.digest());
        assert_ne!(base.digest(), other_executable.digest());
    }

    #[test]
    fn credential_protocol_requires_an_exact_build_probe_receipt() {
        let version = "git version 2.43.0.vendor.1";
        let unadmitted = semantics(version);
        assert_eq!(
            unadmitted.credential_ruleset(),
            GitCredentialProtocolRuleset::Unsupported
        );

        let admission = GitCredentialProtocolAdmission::from_transcript(
            [8; 32],
            version,
            &credential_probe(false),
        )
        .expect("complete exact-build probe");
        let admitted = unadmitted
            .with_credential_protocol_admission(&admission)
            .expect("receipt matches exact build");
        assert_eq!(
            admitted.credential_ruleset(),
            GitCredentialProtocolRuleset::LegacySerial
        );
        assert_ne!(admitted.digest(), semantics(version).digest());

        let other_build = semantics("git version 2.43.0.vendor.2");
        assert_eq!(
            other_build.with_credential_protocol_admission(&admission),
            Err(ResolutionError::BindingMismatch)
        );
        let mut forged_stateful = credential_probe(true);
        forged_stateful.exchanges[2].input =
            b"capability[]=state\nprotocol=https\nhost=gus-probe.invalid\n\n".to_vec();
        assert_eq!(
            GitCredentialProtocolAdmission::from_transcript([8; 32], version, &forged_stateful,),
            Err(ResolutionError::InvalidSnapshot),
            "stateful admission requires an observed state round trip"
        );
        let mut overlapping = credential_probe(false);
        overlapping.exchanges[2].started_order = overlapping.exchanges[1].finished_order;
        assert_eq!(
            GitCredentialProtocolAdmission::from_transcript([8; 32], version, &overlapping),
            Err(ResolutionError::InvalidSnapshot),
            "legacy retries must be observed serially"
        );
        let mut trailing_record = credential_probe(true);
        trailing_record.exchanges[1]
            .output
            .extend_from_slice(b"protocol=https\n");
        assert_eq!(
            GitCredentialProtocolAdmission::from_transcript([8; 32], version, &trailing_record),
            Err(ResolutionError::InvalidSnapshot),
            "bytes after a terminated credential record are not ignored"
        );
        assert_eq!(
            VerifiedGitSemantics::from_version_output(
                [8; 32],
                "git version 2.43.unverified-vendor",
            ),
            Err(ResolutionError::InvalidSnapshot)
        );
    }

    #[test]
    fn http_preflight_evidence_rejects_proxy_and_client_identity_before_git() {
        fn resolve_http(
            args: &[&str],
            entries: Vec<EffectiveConfigEntry>,
            observed: HttpPreflightDisposition,
        ) -> ProfileRequirement {
            let snapshot = ResolverSnapshot::new(
                [1; 32],
                semantics("git version 2.55.0"),
                Some([3; 32]),
                generations(),
                Some("main".to_owned()),
                entries,
                vec![EndpointObservation::new(
                    EndpointRole::Fetch,
                    Transport::Http,
                    [2; 32],
                )],
                vec![HttpPreflightObservation::from_verified_probe(
                    EndpointRole::Fetch,
                    [2; 32],
                    observed,
                )],
            )
            .expect("complete HTTP snapshot");
            GitResolver
                .resolve(InvocationContext::parse(args), snapshot)
                .expect("valid HTTP resolution")
                .profile_requirement()
        }

        assert_eq!(
            resolve_http(
                &["-c", "http.proxy=http://127.0.0.1:8080", "fetch"],
                vec![entry("http.proxy", "http://127.0.0.1:8080")],
                HttpPreflightDisposition::HelperCompatible,
            ),
            ProfileRequirement::Unsupported(RequirementReason::ProxyTransport)
        );
        assert_eq!(
            resolve_http(
                &["-c", "http.sslCert=/managed/client.pem", "fetch"],
                vec![entry("http.sslCert", "/managed/client.pem")],
                HttpPreflightDisposition::HelperCompatible,
            ),
            ProfileRequirement::Unsupported(RequirementReason::PreHandshakeHttpIdentity)
        );
        assert_eq!(
            resolve_http(
                &["fetch"],
                Vec::new(),
                HttpPreflightDisposition::ProxyTransport,
            ),
            ProfileRequirement::Unsupported(RequirementReason::ProxyTransport),
            "platform environment/network observations are also sealed"
        );
        assert_eq!(
            resolve_http(
                &["fetch"],
                Vec::new(),
                HttpPreflightDisposition::HelperCompatible,
            ),
            ProfileRequirement::Deferred(RequirementReason::HttpCredential)
        );

        assert_eq!(
            ResolverSnapshot::new(
                [1; 32],
                semantics("git version 2.55.0"),
                Some([3; 32]),
                generations(),
                Some("main".to_owned()),
                Vec::new(),
                vec![EndpointObservation::new(
                    EndpointRole::Fetch,
                    Transport::Http,
                    [2; 32],
                )],
                Vec::new(),
            ),
            Err(ResolutionError::InvalidSnapshot),
            "an HTTP endpoint cannot omit preflight evidence"
        );
    }
}
