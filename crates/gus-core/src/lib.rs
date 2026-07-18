//! Pure policy core for the GUS Git shim.
//!
//! This crate performs no filesystem access, configuration lookup, process
//! spawning, or shell evaluation. It separates lossless argv parsing from the
//! trusted resolver's immutable endpoint and effective-config evidence.

mod model;
mod parser;
mod policy;
mod resolver;

pub use model::{
    BoundEndpoint, CliBooleanOverride, ConfigEnvOverride, ConfigOverride, EndpointRole,
    GitIdentityDisposition, GlobalOptions, HttpPreflightDisposition, HttpPreflightEvidence,
    InvocationContext, NEUTRAL_REFLOG_EMAIL, NEUTRAL_REFLOG_NAME, NormalizedInvocation, Operation,
    ParseIssue, ProfileRequirement, RequirementReason, ResolutionBinding, ResolutionError,
    ResolutionEvidence, ResolutionRequest, ResolvedEndpoint, ResolvedInvocation,
    SnapshotGenerations, Transport,
};
pub use resolver::{
    EffectiveConfigEntry, EndpointObservation, GitCredentialProtocolAdmission,
    GitCredentialProtocolProbeBehavior, GitCredentialProtocolRuleset, GitResolver,
    GitSemanticRuleset, HttpPreflightObservation, ResolverSnapshot, VerifiedGitSemantics,
};
