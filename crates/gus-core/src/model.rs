use std::{
    ffi::{OsStr, OsString},
    fmt,
};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{parser, policy};

/// Whether a Git invocation may proceed without a selected GUS profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRequirement {
    NotRequired,
    /// Start real Git with the GUS credential boundary installed and select a
    /// profile only if Git actually requests credentials.
    Deferred(RequirementReason),
    Required(RequirementReason),
    /// The operation cannot be made safe by selecting a profile in this
    /// release and must be rejected before real Git starts.
    Unsupported(RequirementReason),
}

/// Identity environment selected before real Git starts. Identity-free and
/// deferred operations still receive a neutral identity so reflog writes never
/// inherit another session's ambient user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitIdentityDisposition {
    NeutralReflog,
    SelectedProfile,
    Rejected,
}

/// Opaque binding issued before a resolver captures filesystem, config, and
/// endpoint observations for one exact invocation.
#[derive(PartialEq, Eq)]
pub struct ResolutionIntent {
    invocation_digest: [u8; 32],
    request_nonce: [u8; 32],
}

impl fmt::Debug for ResolutionIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolutionIntent")
            .field("invocation", &"<bound>")
            .field("request_nonce", &"<redacted>")
            .finish()
    }
}

/// One invocation instance retained while its trusted snapshot is captured.
/// It can be paired only with the unique [`ResolutionIntent`] issued beside it.
#[derive(PartialEq, Eq)]
pub struct ResolutionTarget {
    invocation: InvocationContext,
    request_nonce: [u8; 32],
}

impl fmt::Debug for ResolutionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolutionTarget")
            .field("operation", &self.invocation.operation())
            .field("request_nonce", &"<redacted>")
            .finish()
    }
}

impl ResolutionTarget {
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    pub(crate) fn matches_intent(&self, intent: &ResolutionIntent) -> bool {
        self.request_nonce == intent.request_nonce
            && digest_invocation(&self.invocation.normalized().raw_args) == intent.invocation_digest
    }

    pub(crate) fn into_invocation(self) -> InvocationContext {
        self.invocation
    }
}

pub const NEUTRAL_REFLOG_NAME: &str = "GUS Reflog";
pub const NEUTRAL_REFLOG_EMAIL: &str = "reflog@gus.invalid";

impl ProfileRequirement {
    #[must_use]
    pub const fn identity_disposition(self) -> GitIdentityDisposition {
        match self {
            Self::NotRequired | Self::Deferred(_) => GitIdentityDisposition::NeutralReflog,
            Self::Required(_) => GitIdentityDisposition::SelectedProfile,
            Self::Unsupported(_) => GitIdentityDisposition::Rejected,
        }
    }
}

/// The primary reason a profile is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementReason {
    AuthorIdentity,
    SigningIdentity,
    SshTransport,
    HttpCredential,
    PreHandshakeHttpIdentity,
    ProxyTransport,
    PublishAuthentication,
    UnresolvedTransport,
    UnresolvedIdentityCreation,
    UnverifiedCredentialProtocol,
    AmbiguousConfiguration,
    AmbiguousInvocation,
    UnknownOrExternalCommand,
}

/// Transport after Git configuration, aliases, and URL rewrites are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Local,
    Http,
    Ssh,
    Unknown,
}

/// How an endpoint participates in the resolved Git operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Fetch,
    Push,
    Submodule,
}

/// One effective endpoint after all Git URL and remote expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    role: EndpointRole,
    transport: Transport,
    identity_digest: [u8; 32],
}

impl ResolvedEndpoint {
    const fn new(role: EndpointRole, transport: Transport, identity_digest: [u8; 32]) -> Self {
        Self {
            role,
            transport,
            identity_digest,
        }
    }

    #[must_use]
    pub const fn role(self) -> EndpointRole {
        self.role
    }

    #[must_use]
    pub const fn transport(self) -> Transport {
        self.transport
    }

    #[must_use]
    pub const fn identity_digest(self) -> [u8; 32] {
        self.identity_digest
    }
}

/// Endpoint evidence bound to exactly one resolver request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundEndpoint {
    binding: ResolutionBinding,
    endpoint: ResolvedEndpoint,
}

/// HTTP transport facts which must be known before real Git may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPreflightDisposition {
    /// Direct origin authentication can be deferred to the GUS credential
    /// helper after an HTTP challenge.
    HelperCompatible,
    /// A client identity is needed before the credential helper can run.
    PreHandshakeIdentity,
    /// A proxy or proxy-bypass policy participates in transport selection.
    ProxyTransport,
    /// The resolver could not prove that the transport is helper-compatible.
    Unresolved,
}

/// Resolver-sealed preflight evidence for one exact resolved HTTP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPreflightEvidence {
    role: EndpointRole,
    endpoint_identity_digest: [u8; 32],
    disposition: HttpPreflightDisposition,
}

impl HttpPreflightEvidence {
    #[must_use]
    pub const fn role(self) -> EndpointRole {
        self.role
    }

    #[must_use]
    pub const fn endpoint_identity_digest(self) -> [u8; 32] {
        self.endpoint_identity_digest
    }

    #[must_use]
    pub const fn disposition(self) -> HttpPreflightDisposition {
        self.disposition
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundHttpPreflightEvidence {
    binding: ResolutionBinding,
    evidence: HttpPreflightEvidence,
}

/// Resolver proof about whether a syntactically restricted operation can
/// create an identity-bearing Git object under the complete effective config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityCreationEvidence {
    IdentityFreeProven,
    MayCreateOrUnresolved,
}

/// Security-relevant values from one immutable effective-config snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveConfigEvidence {
    binding: ResolutionBinding,
    merge_ff_only: IdentityCreationEvidence,
    pull_ff_only: IdentityCreationEvidence,
    lightweight_tag: IdentityCreationEvidence,
}

impl EffectiveConfigEvidence {
    const fn new(
        binding: ResolutionBinding,
        merge_ff_only: IdentityCreationEvidence,
        pull_ff_only: IdentityCreationEvidence,
        lightweight_tag: IdentityCreationEvidence,
    ) -> Self {
        Self {
            binding,
            merge_ff_only,
            pull_ff_only,
            lightweight_tag,
        }
    }

    pub(crate) const fn merge_ff_only(self) -> IdentityCreationEvidence {
        self.merge_ff_only
    }

    pub(crate) const fn pull_ff_only(self) -> IdentityCreationEvidence {
        self.pull_ff_only
    }

    pub(crate) const fn lightweight_tag(self) -> IdentityCreationEvidence {
        self.lightweight_tag
    }
}

/// Monotonic generations identifying the repository and effective config read
/// by the resolver. The execution layer must revalidate both before spawning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotGenerations {
    repository: u64,
    config: u64,
}

impl SnapshotGenerations {
    /// Generations start at one; zero means that no snapshot was taken.
    #[must_use]
    pub const fn new(repository: u64, config: u64) -> Option<Self> {
        if repository == 0 || config == 0 {
            None
        } else {
            Some(Self { repository, config })
        }
    }

    #[must_use]
    pub const fn repository(self) -> u64 {
        self.repository
    }

    #[must_use]
    pub const fn config(self) -> u64 {
        self.config
    }
}

/// Immutable identities which bind resolver output to one request and snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionBinding {
    invocation_digest: [u8; 32],
    repository_identity: [u8; 32],
    git_semantics_digest: [u8; 32],
    credential_protocol_admitted: bool,
    config_snapshot_digest: [u8; 32],
    head_state_digest: Option<[u8; 32]>,
    generations: SnapshotGenerations,
}

impl ResolutionBinding {
    #[must_use]
    pub const fn invocation_digest(self) -> [u8; 32] {
        self.invocation_digest
    }

    #[must_use]
    pub const fn repository_identity(self) -> [u8; 32] {
        self.repository_identity
    }

    #[must_use]
    pub const fn git_semantics_digest(self) -> [u8; 32] {
        self.git_semantics_digest
    }

    #[must_use]
    pub const fn credential_protocol_admitted(self) -> bool {
        self.credential_protocol_admitted
    }

    #[must_use]
    pub const fn config_snapshot_digest(self) -> [u8; 32] {
        self.config_snapshot_digest
    }

    #[must_use]
    pub const fn head_state_digest(self) -> Option<[u8; 32]> {
        self.head_state_digest
    }

    #[must_use]
    pub const fn generations(self) -> SnapshotGenerations {
        self.generations
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResolutionError {
    #[error("resolver evidence belongs to a different request or snapshot")]
    BindingMismatch,
    #[error("an identity-free merge or pull proof requires a bound HEAD state")]
    HeadStateRequired,
    #[error("resolved endpoint roles or count do not match the Git operation")]
    EndpointSetMismatch,
    #[error("resolver snapshot is missing a required file or endpoint identity")]
    InvalidSnapshot,
    #[error("a unique resolver capture intent could not be issued")]
    IntentUnavailable,
}

/// Output of the trusted resolver after fixed Git has expanded configuration,
/// aliases, remotes, and `url.*.insteadOf`/`pushInsteadOf` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionEvidence {
    binding: ResolutionBinding,
    endpoints: Vec<ResolvedEndpoint>,
    effective_config: EffectiveConfigEvidence,
    http_preflight: Vec<HttpPreflightEvidence>,
    generations: SnapshotGenerations,
}

impl ResolutionEvidence {
    #[must_use]
    pub const fn binding(&self) -> ResolutionBinding {
        self.binding
    }

    #[must_use]
    pub fn endpoints(&self) -> &[ResolvedEndpoint] {
        &self.endpoints
    }

    #[must_use]
    pub(crate) const fn effective_config(&self) -> EffectiveConfigEvidence {
        self.effective_config
    }

    #[must_use]
    pub fn http_preflight(&self) -> &[HttpPreflightEvidence] {
        &self.http_preflight
    }

    #[must_use]
    pub const fn generations(&self) -> SnapshotGenerations {
        self.generations
    }
}

/// A normalized `git -c name=value` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOverride {
    pub name: String,
    pub value: OsString,
}

/// A normalized `git --config-env=name=ENV_VAR` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEnvOverride {
    pub name: String,
    pub environment_variable: String,
}

/// Git global options relevant to repository and policy resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalOptions {
    /// Ordered `-C` values. Git applies repeated `-C` options cumulatively.
    pub directory_changes: Vec<OsString>,
    /// Last `--git-dir` value, matching Git's effective-option behavior.
    pub git_dir: Option<OsString>,
    /// Last `--work-tree` value, matching Git's effective-option behavior.
    pub work_tree: Option<OsString>,
    /// Last `--namespace` value. The resolver binds this to the repository
    /// snapshot before any endpoint or ref decision is trusted.
    pub namespace: Option<OsString>,
    /// Explicit exec path. It is parsed losslessly but remains conservative
    /// until executable provenance is verified.
    pub exec_path: Option<OsString>,
    pub config_overrides: Vec<ConfigOverride>,
    pub config_env_overrides: Vec<ConfigEnvOverride>,
    /// Recognized global flags which do not carry values.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIssue {
    EmptyInvocation,
    InvalidEncoding,
    MissingOptionValue,
    MalformedOptionValue,
    UnknownGlobalOption,
}

/// Command category used by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Informational,
    ReadOnly,
    WorkingTree,
    ConfigRead,
    ConfigWriteOrUnknown,
    Fetch,
    Clone,
    LsRemote,
    Pull {
        ff_only_candidate: bool,
        rebase: CliBooleanOverride,
        autostash: CliBooleanOverride,
    },
    Push,
    Commit,
    CommitTree,
    Merge {
        ff_only_candidate: bool,
    },
    HistoryRewrite,
    Stash,
    /// The argv requests a lightweight tag, but effective `tag.gpgSign` may
    /// still promote it to an identity-bearing signed tag.
    LightweightTagCandidate,
    AnnotatedTag,
    SignedTag,
    Unknown,
}

/// Last explicit command-line value for a Git boolean option. Keeping this in
/// the normalized operation lets the resolver apply Git's CLI-over-config
/// precedence without reparsing lossy strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliBooleanOverride {
    Unspecified,
    Enabled,
    Disabled,
}

/// Result of syntactically normalizing a Git invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedInvocation {
    /// Exact argv following the executable name. It is never lossily decoded.
    pub raw_args: Vec<OsString>,
    pub global: GlobalOptions,
    pub command: Option<String>,
    pub command_args: Vec<OsString>,
    pub operation: Operation,
    pub issue: Option<ParseIssue>,
}

/// Syntactic evidence only. Network and config-sensitive operations remain
/// conservative until converted to [`ResolvedInvocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationContext {
    invocation: NormalizedInvocation,
}

impl InvocationContext {
    /// Parse arguments following the `git` executable name without lossy
    /// Unicode conversion. No config lookup or process execution occurs.
    pub fn parse<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        parser::parse(args)
    }

    #[must_use]
    pub fn normalized(&self) -> &NormalizedInvocation {
        &self.invocation
    }

    #[must_use]
    pub fn operation(&self) -> Operation {
        self.invocation.operation
    }

    /// A pre-resolution decision. Any decision depending on Git config or an
    /// endpoint is deliberately fail-closed here.
    #[must_use]
    pub fn profile_requirement(&self) -> ProfileRequirement {
        policy::unresolved_profile_requirement(self)
    }

    /// Splits this invocation into a retained target and a unique one-shot
    /// binding that a resolver snapshot must consume.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionError::IntentUnavailable`] if the operating system
    /// cannot provide a fresh nonce. No resolver observation should start in
    /// that case.
    pub fn begin_resolution_capture(
        self,
    ) -> Result<(ResolutionTarget, ResolutionIntent), ResolutionError> {
        let mut request_nonce = [0_u8; 32];
        getrandom::fill(&mut request_nonce).map_err(|_| ResolutionError::IntentUnavailable)?;
        if request_nonce == [0; 32] {
            return Err(ResolutionError::IntentUnavailable);
        }
        let invocation_digest = digest_invocation(&self.invocation.raw_args);
        Ok((
            ResolutionTarget {
                invocation: self,
                request_nonce,
            },
            ResolutionIntent {
                invocation_digest,
                request_nonce,
            },
        ))
    }

    /// Start a resolver-owned request bound to one repository/config/HEAD
    /// snapshot. Resolver evidence can only be constructed by consuming this
    /// request, preventing evidence produced for another invocation from being
    /// attached accidentally.
    #[must_use]
    pub(crate) fn begin_resolution(
        self,
        repository_identity: [u8; 32],
        git_semantics_digest: [u8; 32],
        credential_protocol_admitted: bool,
        config_snapshot_digest: [u8; 32],
        head_state_digest: Option<[u8; 32]>,
        generations: SnapshotGenerations,
    ) -> ResolutionRequest {
        let binding = ResolutionBinding {
            invocation_digest: digest_invocation(&self.invocation.raw_args),
            repository_identity,
            git_semantics_digest,
            credential_protocol_admitted,
            config_snapshot_digest,
            head_state_digest,
            generations,
        };
        ResolutionRequest {
            invocation: self,
            binding,
        }
    }

    pub(crate) fn from_normalized(invocation: NormalizedInvocation) -> Self {
        Self { invocation }
    }
}

/// A resolver request whose type owns both the parsed invocation and the
/// immutable snapshot binding. It is consumed exactly once when evidence is
/// finalized.
#[derive(Debug)]
pub struct ResolutionRequest {
    invocation: InvocationContext,
    binding: ResolutionBinding,
}

impl ResolutionRequest {
    #[must_use]
    pub const fn binding(&self) -> ResolutionBinding {
        self.binding
    }

    #[must_use]
    pub(crate) const fn bind_endpoint(
        &self,
        role: EndpointRole,
        transport: Transport,
        identity_digest: [u8; 32],
    ) -> BoundEndpoint {
        BoundEndpoint {
            binding: self.binding,
            endpoint: ResolvedEndpoint::new(role, transport, identity_digest),
        }
    }

    pub(crate) const fn bind_effective_config(
        &self,
        merge_ff_only: IdentityCreationEvidence,
        pull_ff_only: IdentityCreationEvidence,
        lightweight_tag: IdentityCreationEvidence,
    ) -> EffectiveConfigEvidence {
        EffectiveConfigEvidence::new(self.binding, merge_ff_only, pull_ff_only, lightweight_tag)
    }

    pub(crate) const fn bind_http_preflight(
        &self,
        role: EndpointRole,
        endpoint_identity_digest: [u8; 32],
        disposition: HttpPreflightDisposition,
    ) -> BoundHttpPreflightEvidence {
        BoundHttpPreflightEvidence {
            binding: self.binding,
            evidence: HttpPreflightEvidence {
                role,
                endpoint_identity_digest,
                disposition,
            },
        }
    }

    /// Finalizes evidence produced by the sealed resolver implementation.
    ///
    /// # Errors
    ///
    /// Rejects evidence from another request, incomplete HEAD evidence for an
    /// identity-free integration proof, or endpoint roles/counts that do not
    /// match the parsed operation.
    pub(crate) fn resolve(
        self,
        endpoints: Vec<BoundEndpoint>,
        effective_config: EffectiveConfigEvidence,
        http_preflight: Vec<BoundHttpPreflightEvidence>,
    ) -> Result<ResolvedInvocation, ResolutionError> {
        if effective_config.binding != self.binding
            || endpoints
                .iter()
                .any(|endpoint| endpoint.binding != self.binding)
            || http_preflight
                .iter()
                .any(|evidence| evidence.binding != self.binding)
        {
            return Err(ResolutionError::BindingMismatch);
        }

        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| endpoint.endpoint)
            .collect::<Vec<_>>();
        if !endpoint_set_matches(self.invocation.operation(), &endpoints) {
            return Err(ResolutionError::EndpointSetMismatch);
        }
        let http_preflight = http_preflight
            .into_iter()
            .map(|evidence| evidence.evidence)
            .collect::<Vec<_>>();
        if !http_preflight_set_matches(&endpoints, &http_preflight) {
            return Err(ResolutionError::EndpointSetMismatch);
        }

        let identity_free_integration = match self.invocation.operation() {
            Operation::Merge {
                ff_only_candidate: true,
            } => effective_config.merge_ff_only == IdentityCreationEvidence::IdentityFreeProven,
            Operation::Pull {
                ff_only_candidate: true,
                ..
            } => effective_config.pull_ff_only == IdentityCreationEvidence::IdentityFreeProven,
            _ => false,
        };
        if identity_free_integration && self.binding.head_state_digest.is_none() {
            return Err(ResolutionError::HeadStateRequired);
        }

        Ok(ResolvedInvocation {
            invocation: self.invocation,
            evidence: ResolutionEvidence {
                binding: self.binding,
                endpoints,
                effective_config,
                http_preflight,
                generations: self.binding.generations,
            },
        })
    }
}

fn http_preflight_set_matches(
    endpoints: &[ResolvedEndpoint],
    preflight: &[HttpPreflightEvidence],
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

fn endpoint_set_matches(operation: Operation, endpoints: &[ResolvedEndpoint]) -> bool {
    match operation {
        Operation::Fetch | Operation::Clone | Operation::Pull { .. } => {
            endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Fetch)
                && endpoints.iter().all(|endpoint| {
                    matches!(endpoint.role, EndpointRole::Fetch | EndpointRole::Submodule)
                })
        }
        Operation::LsRemote => {
            !endpoints.is_empty()
                && endpoints
                    .iter()
                    .all(|endpoint| endpoint.role == EndpointRole::Fetch)
        }
        Operation::Push => {
            endpoints
                .iter()
                .any(|endpoint| endpoint.role == EndpointRole::Push)
                && endpoints.iter().all(|endpoint| {
                    matches!(endpoint.role, EndpointRole::Push | EndpointRole::Submodule)
                })
        }
        _ => endpoints.is_empty(),
    }
}

fn digest_invocation(args: &[OsString]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gus.normalized-invocation.v1\0");
    for argument in args {
        let bytes = argument.as_os_str().as_encoded_bytes();
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    digest.finalize().into()
}

/// Invocation and all immutable evidence used by the final policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInvocation {
    invocation: InvocationContext,
    evidence: ResolutionEvidence,
}

impl ResolvedInvocation {
    #[must_use]
    pub fn invocation(&self) -> &InvocationContext {
        &self.invocation
    }

    #[must_use]
    pub const fn evidence(&self) -> &ResolutionEvidence {
        &self.evidence
    }

    #[must_use]
    pub fn profile_requirement(&self) -> ProfileRequirement {
        policy::resolved_profile_requirement(self)
    }
}
