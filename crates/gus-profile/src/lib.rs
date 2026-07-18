//! Validated, serializable profile types for GUS.
//!
//! Transport authentication, commit signing, and HTTP credentials are
//! intentionally represented by distinct types. A caller must opt in to
//! reusing the same underlying key; GUS never infers that relationship.

mod model;
mod validation;

pub use model::{
    CredentialBackend, CredentialBinding, CredentialProtocol, ExecutableRef, HttpIdentity,
    PersonIdentity, Profile, ProfileId, ProfileSet, SigningFormat, SigningIdentity, SigningPolicy,
    SshIdentity, SshIdentitySource,
};
pub use validation::ValidationError;
