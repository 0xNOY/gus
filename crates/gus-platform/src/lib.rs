//! Native operating-system observations used to derive GUS session identity.
//!
//! Values in this crate are evidence produced by an operating-system backend,
//! not claims accepted from IPC, environment variables, or command-line
//! arguments. Their constructors are deliberately private. The identities are
//! suitable for equality and hashing, but they do not make processes sharing
//! one OS user into mutually distrustful security principals.
//! FreeBSD observations are scoped to one prison: the kernel reports the
//! observer's current prison as JID zero, so brokers, sockets, and stored
//! session authority must never be shared across prison boundaries.

use std::{fmt, num::NonZeroU32, num::NonZeroU64};

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
mod bsd_model;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "freebsd")]
mod peer_freebsd;
#[cfg(target_os = "linux")]
mod peer_linux;
#[cfg(target_os = "macos")]
mod peer_macos;
#[cfg(target_os = "windows")]
mod peer_windows;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(any(target_os = "windows", test))]
mod windows_model;

#[cfg(target_os = "freebsd")]
pub use peer_freebsd::{AuthenticatedUnixStream, PeerAuthenticationError};
#[cfg(target_os = "linux")]
pub use peer_linux::{AuthenticatedUnixStream, PeerAuthenticationError};
#[cfg(target_os = "macos")]
pub use peer_macos::{AuthenticatedUnixStream, PeerAuthenticationError};
#[cfg(target_os = "windows")]
pub use peer_windows::{
    AuthenticatedNamedPipe, ConnectedClientPipe, ConnectedServerPipe, NamedPipeListener,
    PeerAuthenticationError, connect_named_pipe,
};

const IDENTITY_DIGEST_BYTES: usize = 32;

/// Operating-system family that produced an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PlatformFamily {
    Linux,
    MacOs,
    FreeBsd,
    Windows,
    Other,
}

/// Opaque identity for one local OS user in this observer's native isolation
/// boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsUserIdentity {
    family: PlatformFamily,
    digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl OsUserIdentity {
    #[must_use]
    pub const fn family(self) -> PlatformFamily {
        self.family
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self {
            family,
            digest: identity_digest(b"gus.platform.user.v1", family, native),
        }
    }
}

impl fmt::Debug for OsUserIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OsUserIdentity")
            .field("family", &self.family)
            .field("opaque", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Opaque identity for the native time domain of a process start value.
///
/// Linux and FreeBSD bind a host boot ID to boot-relative process time.
/// Platforms whose process creation time has an absolute epoch bind that epoch
/// instead. Consumers compare this value together with `start_time` and never
/// interpret either field in isolation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessTimeDomainIdentity([u8; IDENTITY_DIGEST_BYTES]);

impl ProcessTimeDomainIdentity {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self(identity_digest(
            b"gus.platform.process-time-domain.v1",
            family,
            native,
        ))
    }
}

impl fmt::Debug for ProcessTimeDomainIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessTimeDomainIdentity([REDACTED])")
    }
}

/// Identity of a process that remains stable across PID reuse.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    time_domain: ProcessTimeDomainIdentity,
    pid: NonZeroU32,
    start_time: NonZeroU64,
    user: OsUserIdentity,
}

impl ProcessIdentity {
    #[must_use]
    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    #[must_use]
    pub const fn start_time(self) -> NonZeroU64 {
        self.start_time
    }

    #[must_use]
    pub const fn user(self) -> OsUserIdentity {
        self.user
    }

    #[must_use]
    pub const fn time_domain(self) -> ProcessTimeDomainIdentity {
        self.time_domain
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    const fn from_observation(
        time_domain: ProcessTimeDomainIdentity,
        pid: NonZeroU32,
        start_time: NonZeroU64,
        user: OsUserIdentity,
    ) -> Self {
        Self {
            time_domain,
            pid,
            start_time,
            user,
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "windows"))]
fn process_identity_proof_digest(identity: ProcessIdentity) -> [u8; IDENTITY_DIGEST_BYTES] {
    let mut native = [0_u8; 76];
    native[0..32].copy_from_slice(&identity.time_domain.0);
    native[32..36].copy_from_slice(&identity.pid.get().to_le_bytes());
    native[36..44].copy_from_slice(&identity.start_time.get().to_le_bytes());
    native[44..76].copy_from_slice(&identity.user.digest);
    identity_digest(
        b"gus.platform.peer-process-proof.v1",
        identity.user.family,
        &native,
    )
}

impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessIdentity")
            .field("pid", &self.pid)
            .field("start_time", &self.start_time)
            .field("time_domain", &self.time_domain)
            .field("user", &self.user)
            .finish()
    }
}

/// Opaque identity for a controlling terminal or console.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalIdentity {
    family: PlatformFamily,
    digest: [u8; IDENTITY_DIGEST_BYTES],
}

impl TerminalIdentity {
    #[must_use]
    pub const fn family(self) -> PlatformFamily {
        self.family
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    fn from_native_bytes(family: PlatformFamily, native: &[u8]) -> Self {
        Self {
            family,
            digest: identity_digest(b"gus.platform.terminal.v1", family, native),
        }
    }
}

impl fmt::Debug for TerminalIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalIdentity")
            .field("family", &self.family)
            .field("opaque", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A terminal or console session anchored to its live native root process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSessionIdentity {
    terminal: TerminalIdentity,
    anchor_process: ProcessIdentity,
}

impl TerminalSessionIdentity {
    #[must_use]
    pub const fn terminal(self) -> TerminalIdentity {
        self.terminal
    }

    #[must_use]
    pub const fn anchor_process(self) -> ProcessIdentity {
        self.anchor_process
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    const fn from_observation(terminal: TerminalIdentity, anchor_process: ProcessIdentity) -> Self {
        Self {
            terminal,
            anchor_process,
        }
    }
}

/// OS-derived facts for the process which invoked GUS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalSessionObservation {
    caller: ProcessIdentity,
    parent_pid: Option<NonZeroU32>,
    terminal: Option<TerminalSessionIdentity>,
}

impl LocalSessionObservation {
    #[must_use]
    pub const fn caller(self) -> ProcessIdentity {
        self.caller
    }

    #[must_use]
    pub const fn parent_pid(self) -> Option<NonZeroU32> {
        self.parent_pid
    }

    #[must_use]
    pub const fn terminal_session(self) -> Option<TerminalSessionIdentity> {
        self.terminal
    }

    #[must_use]
    pub const fn has_terminal_session(self) -> bool {
        self.terminal.is_some()
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows",
        test
    ))]
    const fn from_observation(
        caller: ProcessIdentity,
        parent_pid: Option<NonZeroU32>,
        terminal: Option<TerminalSessionIdentity>,
    ) -> Self {
        Self {
            caller,
            parent_pid,
            terminal,
        }
    }
}

/// Native observer for the current GUS process.
#[derive(Debug, Default, Clone, Copy)]
pub struct CurrentSessionObserver;

impl CurrentSessionObserver {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Observes the current process and its native terminal-session anchor.
    ///
    /// # Errors
    ///
    /// Fails closed if the backend is unavailable, kernel data is malformed,
    /// the process changes during observation, or a terminal anchor cannot be
    /// bound to the same user and terminal session.
    pub fn observe(self) -> Result<LocalSessionObservation, ObservationError> {
        #[cfg(target_os = "linux")]
        {
            linux::observe_current()
        }
        #[cfg(target_os = "windows")]
        {
            windows::observe_current()
        }
        #[cfg(target_os = "macos")]
        {
            macos::observe_current()
        }
        #[cfg(target_os = "freebsd")]
        {
            freebsd::observe_current()
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "windows"
        )))]
        {
            Err(ObservationError::UnsupportedPlatform)
        }
    }
}

/// Native observer for a process identifier.
///
/// A PID is not itself an identity. The resulting value also binds the native
/// process start time, OS user, and platform time domain so a recycled PID does
/// not compare equal to the original process. This observer does **not** prove
/// that a PID came from a particular socket or pipe; IPC authority must be
/// created by a platform transport which binds kernel peer credentials to a
/// process-liveness handle or challenge proof before decoding a frame.
#[derive(Debug, Clone, Copy)]
pub struct NativeProcessObserver {
    pid: NonZeroU32,
}

impl NativeProcessObserver {
    #[must_use]
    pub const fn new(pid: NonZeroU32) -> Self {
        Self { pid }
    }

    /// Observes the process which owns this PID at the start of observation,
    /// without trusting process-supplied command-line or environment data.
    ///
    /// # Errors
    ///
    /// Fails closed if the platform cannot observe the process, access is
    /// denied, or the process exits or changes during the observation window.
    pub fn observe(self) -> Result<ProcessIdentity, ObservationError> {
        #[cfg(target_os = "linux")]
        {
            linux::observe_process(self.pid)
        }
        #[cfg(target_os = "windows")]
        {
            windows::observe_target_process(self.pid)
        }
        #[cfg(target_os = "macos")]
        {
            macos::observe_process(self.pid)
        }
        #[cfg(target_os = "freebsd")]
        {
            freebsd::observe_process(self.pid)
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "windows"
        )))]
        {
            Err(ObservationError::UnsupportedPlatform)
        }
    }
}

/// Bounded native resource consulted during observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationResource {
    ProcessTimeDomain,
    CallerProcess,
    CallerUser,
    ProcessAncestry,
    TerminalSession,
    TerminalAnchorProcess,
    TerminalAnchorUser,
    TargetProcess,
    TargetUser,
}

impl fmt::Display for ObservationResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ProcessTimeDomain => "process time domain",
            Self::CallerProcess => "caller process",
            Self::CallerUser => "caller user",
            Self::ProcessAncestry => "process ancestry",
            Self::TerminalSession => "terminal session",
            Self::TerminalAnchorProcess => "terminal anchor process",
            Self::TerminalAnchorUser => "terminal anchor user",
            Self::TargetProcess => "target process",
            Self::TargetUser => "target process user",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationError {
    #[error("native session observation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("failed to read {resource}: {kind:?}")]
    Read {
        resource: ObservationResource,
        kind: std::io::ErrorKind,
    },
    #[error("{resource} exceeded its native size bound")]
    Oversized { resource: ObservationResource },
    #[error("{resource} had a malformed native representation")]
    Malformed { resource: ObservationResource },
    #[error("observed process changed during observation")]
    ProcessChanged,
    #[error("terminal anchor changed during observation")]
    TerminalAnchorChanged,
    #[error("terminal is not bound to the observed user and anchor process")]
    TerminalBindingMismatch,
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows",
    test
))]
fn identity_digest(
    domain: &[u8],
    family: PlatformFamily,
    native: &[u8],
) -> [u8; IDENTITY_DIGEST_BYTES] {
    let family_tag: &[u8] = match family {
        PlatformFamily::Linux => b"linux",
        PlatformFamily::MacOs => b"macos",
        PlatformFamily::FreeBsd => b"freebsd",
        PlatformFamily::Windows => b"windows",
        PlatformFamily::Other => b"other",
    };
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(family_tag.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(family_tag);
    hasher.update(
        u64::try_from(native.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(native);
    hasher.finalize().into()
}

#[cfg(test)]
mod process_observer_tests {
    use super::*;

    #[test]
    fn native_process_identity_is_stable_and_redacts_its_user() {
        let pid = NonZeroU32::new(std::process::id()).expect("current process PID is nonzero");
        let first = NativeProcessObserver::new(pid)
            .observe()
            .expect("first process observation");
        let second = NativeProcessObserver::new(pid)
            .observe()
            .expect("second process observation");

        assert_eq!(first, second);
        assert_eq!(first.pid(), pid);
        let debug = format!("{first:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("digest"));
    }
}
