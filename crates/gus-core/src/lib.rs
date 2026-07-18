//! Pure policy core for the GUS Git shim.
//!
//! This crate performs no filesystem access, configuration lookup, process
//! spawning, or shell evaluation. It separates lossless argv parsing from the
//! trusted resolver's immutable endpoint and effective-config evidence.

mod model;
mod parser;
mod policy;

pub use model::{
    ConfigEnvOverride, ConfigOverride, EffectiveConfigEvidence, EndpointRole, GlobalOptions,
    IdentityCreationEvidence, InvocationContext, NormalizedInvocation, Operation, ParseIssue,
    ProfileRequirement, RequirementReason, ResolutionBinding, ResolutionEvidence,
    ResolutionRequest, ResolvedEndpoint, ResolvedInvocation, SnapshotGenerations, Transport,
};
