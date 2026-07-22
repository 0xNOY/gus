use std::process::ExitCode;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::ffi::OsString;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use gus_core::{NEUTRAL_REFLOG_EMAIL, NEUTRAL_REFLOG_NAME, ProfileRequirement, RequirementReason};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use gus_platform::{ExecutableExclusionSet, VerifiedRealGit};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use gus_shim::{InitialRoute, LocalPolicyAdmission, ShimInvocation};

fn main() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        run_unix()
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        eprintln!("GUS_E_PLATFORM_UNSUPPORTED: the Git shim is not implemented on this platform");
        ExitCode::from(126)
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn run_unix() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match ShimInvocation::parse(&arguments).route() {
        InitialRoute::Forward(admission) => execute_git(admission),
        InitialRoute::Resolve(required) => {
            eprintln!(
                "GUS_E_SELECTION_REQUIRED: {}; repository/profile resolution is not available in this build, so Git was not started",
                requirement_message(required.invocation().profile_requirement())
            );
            ExitCode::from(125)
        }
        InitialRoute::Reject(rejection) => {
            eprintln!(
                "GUS_E_POLICY_REJECTED: {}; Git was not started",
                reason_message(rejection.reason())
            );
            ExitCode::from(125)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn execute_git(admission: LocalPolicyAdmission) -> ExitCode {
    let arguments = admission.into_arguments();
    let current = match std::env::current_exe() {
        Ok(current) => current,
        Err(error) => return launch_error("resolve the running shim", &error),
    };
    let Some(owned_root) = current.parent() else {
        return launch_message("the running shim has no installation directory");
    };
    let exclusions = match ExecutableExclusionSet::new(owned_root, 1) {
        Ok(exclusions) => exclusions,
        Err(error) => return launch_error("build the GUS exclusion set", &error),
    };
    let git = match VerifiedRealGit::discover_system(exclusions) {
        Ok(git) => git,
        Err(error) => return launch_error("verify the fixed system Git", &error),
    };

    let mut forwarded = Vec::with_capacity(arguments.len() + 1);
    forwarded.push(OsString::from("git"));
    forwarded.extend(arguments);
    let environment = neutral_environment();
    match git.exec(&forwarded, &environment) {
        Ok(never) => match never {},
        Err(error) => launch_error("execute the retained system Git", &error),
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const fn reason_message(reason: RequirementReason) -> &'static str {
    match reason {
        RequirementReason::AuthorIdentity => "this Git operation needs an author identity",
        RequirementReason::SigningIdentity => "this Git operation needs a signing identity",
        RequirementReason::SshTransport => "this Git operation needs an SSH identity",
        RequirementReason::HttpCredential => "this Git operation may need an HTTP credential",
        RequirementReason::PreHandshakeHttpIdentity => {
            "this Git operation needs an HTTP identity before authentication"
        }
        RequirementReason::ProxyTransport => "this Git operation uses an unsupported proxy path",
        RequirementReason::PublishAuthentication => {
            "this Git operation needs publication authentication"
        }
        RequirementReason::UnresolvedTransport => {
            "the effective remote transport has not been resolved"
        }
        RequirementReason::UnresolvedIdentityCreation => {
            "the effective Git configuration may create an identity-bearing object"
        }
        RequirementReason::UnverifiedCredentialProtocol => {
            "the Git credential protocol has not been verified"
        }
        RequirementReason::AmbiguousConfiguration => "the effective Git configuration is ambiguous",
        RequirementReason::AmbiguousInvocation => "the Git invocation is ambiguous",
        RequirementReason::UnknownOrExternalCommand => {
            "the Git command is unknown or externally implemented"
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const fn requirement_message(requirement: ProfileRequirement) -> &'static str {
    match requirement {
        ProfileRequirement::Deferred(reason)
        | ProfileRequirement::Required(reason)
        | ProfileRequirement::Unsupported(reason) => reason_message(reason),
        ProfileRequirement::NotRequired => "this Git operation needs trusted repository evidence",
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn neutral_environment() -> Vec<(OsString, OsString)> {
    const REMOVED: &[&str] = &[
        "EMAIL",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_NAME",
    ];
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| !REMOVED.iter().any(|removed| name == removed))
        .collect::<Vec<_>>();
    environment.extend([
        (
            OsString::from("GIT_AUTHOR_NAME"),
            OsString::from(NEUTRAL_REFLOG_NAME),
        ),
        (
            OsString::from("GIT_AUTHOR_EMAIL"),
            OsString::from(NEUTRAL_REFLOG_EMAIL),
        ),
        (
            OsString::from("GIT_COMMITTER_NAME"),
            OsString::from(NEUTRAL_REFLOG_NAME),
        ),
        (
            OsString::from("GIT_COMMITTER_EMAIL"),
            OsString::from(NEUTRAL_REFLOG_EMAIL),
        ),
    ]);
    environment
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn launch_error(action: &str, error: &dyn std::error::Error) -> ExitCode {
    eprintln!("GUS_E_REAL_GIT: failed to {action}: {error}");
    ExitCode::from(126)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn launch_message(message: &str) -> ExitCode {
    eprintln!("GUS_E_REAL_GIT: {message}");
    ExitCode::from(126)
}
