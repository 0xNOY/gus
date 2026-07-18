use std::ffi::{OsStr, OsString};

use sha2::{Digest, Sha256};

use crate::{parser, policy};

/// Whether a Git invocation may proceed without a selected GUS profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRequirement {
    NotRequired,
    /// Start real Git with the GUS credential boundary installed and select a
    /// profile only if Git actually requests credentials.
    Deferred(RequirementReason),
    Required(RequirementReason),
}

/// The primary reason a profile is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementReason {
    AuthorIdentity,
    SigningIdentity,
    SshTransport,
    HttpCredential,
    PublishAuthentication,
    UnresolvedTransport,
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
    #[must_use]
    pub const fn new(role: EndpointRole, transport: Transport, identity_digest: [u8; 32]) -> Self {
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

/// Resolver proof about whether a syntactically restricted operation can
/// create an identity-bearing Git object under the complete effective config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCreationEvidence {
    IdentityFreeProven,
    MayCreateOrUnresolved,
}

/// Security-relevant values from one immutable effective-config snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveConfigEvidence {
    merge_ff_only: IdentityCreationEvidence,
    pull_ff_only: IdentityCreationEvidence,
    lightweight_tag: IdentityCreationEvidence,
}

impl EffectiveConfigEvidence {
    #[must_use]
    pub const fn new(
        merge_ff_only: IdentityCreationEvidence,
        pull_ff_only: IdentityCreationEvidence,
        lightweight_tag: IdentityCreationEvidence,
    ) -> Self {
        Self {
            merge_ff_only,
            pull_ff_only,
            lightweight_tag,
        }
    }

    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(
            IdentityCreationEvidence::MayCreateOrUnresolved,
            IdentityCreationEvidence::MayCreateOrUnresolved,
            IdentityCreationEvidence::MayCreateOrUnresolved,
        )
    }

    #[must_use]
    pub const fn merge_ff_only(self) -> IdentityCreationEvidence {
        self.merge_ff_only
    }

    #[must_use]
    pub const fn pull_ff_only(self) -> IdentityCreationEvidence {
        self.pull_ff_only
    }

    #[must_use]
    pub const fn lightweight_tag(self) -> IdentityCreationEvidence {
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
    config_snapshot_digest: [u8; 32],
    head_state_digest: Option<[u8; 32]>,
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
    pub const fn config_snapshot_digest(self) -> [u8; 32] {
        self.config_snapshot_digest
    }

    #[must_use]
    pub const fn head_state_digest(self) -> Option<[u8; 32]> {
        self.head_state_digest
    }
}

/// Output of the trusted resolver after fixed Git has expanded configuration,
/// aliases, remotes, and `url.*.insteadOf`/`pushInsteadOf` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionEvidence {
    binding: ResolutionBinding,
    endpoints: Vec<ResolvedEndpoint>,
    effective_config: EffectiveConfigEvidence,
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
    pub const fn effective_config(&self) -> EffectiveConfigEvidence {
        self.effective_config
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
    ReadOnly,
    WorkingTree,
    ConfigRead,
    ConfigWriteOrUnknown,
    Fetch,
    Clone,
    LsRemote,
    Pull {
        ff_only_candidate: bool,
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

    /// Start a resolver-owned request bound to one repository/config/HEAD
    /// snapshot. Resolver evidence can only be constructed by consuming this
    /// request, preventing evidence produced for another invocation from being
    /// attached accidentally.
    #[must_use]
    pub fn begin_resolution(
        self,
        repository_identity: [u8; 32],
        config_snapshot_digest: [u8; 32],
        head_state_digest: Option<[u8; 32]>,
        generations: SnapshotGenerations,
    ) -> ResolutionRequest {
        let binding = ResolutionBinding {
            invocation_digest: digest_invocation(&self.invocation.raw_args),
            repository_identity,
            config_snapshot_digest,
            head_state_digest,
        };
        ResolutionRequest {
            invocation: self,
            binding,
            generations,
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
    generations: SnapshotGenerations,
}

impl ResolutionRequest {
    #[must_use]
    pub const fn binding(&self) -> ResolutionBinding {
        self.binding
    }

    #[must_use]
    pub fn resolve(
        self,
        endpoints: Vec<ResolvedEndpoint>,
        effective_config: EffectiveConfigEvidence,
    ) -> ResolvedInvocation {
        ResolvedInvocation {
            invocation: self.invocation,
            evidence: ResolutionEvidence {
                binding: self.binding,
                endpoints,
                effective_config,
                generations: self.generations,
            },
        }
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
