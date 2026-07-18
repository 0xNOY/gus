use std::num::{NonZeroU32, NonZeroU64};

use crate::{
    LocalSessionObservation, ObservationError, ObservationResource, OsUserIdentity, PlatformFamily,
    ProcessIdentity, ProcessTimeDomainIdentity, TerminalIdentity, TerminalSessionIdentity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessFacts {
    pub(super) pid: NonZeroU32,
    pub(super) parent_pid: Option<NonZeroU32>,
    pub(super) process_group_id: NonZeroU32,
    pub(super) session_id: NonZeroU32,
    pub(super) terminal_device: Option<u64>,
    pub(super) terminal_session_id: Option<NonZeroU32>,
    pub(super) has_control_terminal: bool,
    pub(super) is_session_leader: bool,
    pub(super) start_time: NonZeroU64,
    pub(super) effective_uid: u32,
    /// Native namespace discriminator visible to this observer. This is zero
    /// on macOS. FreeBSD reports a target jail ID to a host observer but zero
    /// for the observer's own prison, so it is not a global jail identity.
    pub(super) user_namespace: u32,
}

pub(super) fn timeval_start(
    seconds: i128,
    microseconds: i128,
    resource: ObservationResource,
) -> Result<NonZeroU64, ObservationError> {
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(ObservationError::Malformed { resource });
    }
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(microseconds))
        .and_then(|value| u64::try_from(value).ok())
        .and_then(NonZeroU64::new)
        .ok_or(ObservationError::Malformed { resource })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TerminalFacts {
    pub(super) terminal_device: u64,
    pub(super) session_id: NonZeroU32,
    pub(super) device_binding_matches: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalEvidence {
    Detached {
        second: Option<TerminalFacts>,
    },
    Attached {
        first: TerminalFacts,
        leader_first: ProcessFacts,
        leader_second: ProcessFacts,
        second: Option<TerminalFacts>,
    },
}

pub(super) fn assemble_observation(
    family: PlatformFamily,
    time_domain: ProcessTimeDomainIdentity,
    caller_first: ProcessFacts,
    terminal: TerminalEvidence,
    caller_second: ProcessFacts,
) -> Result<LocalSessionObservation, ObservationError> {
    if caller_first != caller_second {
        return Err(ObservationError::ProcessChanged);
    }

    let mut user_native = [0_u8; 8];
    user_native[0..4].copy_from_slice(&caller_first.effective_uid.to_le_bytes());
    user_native[4..8].copy_from_slice(&caller_first.user_namespace.to_le_bytes());
    let user = OsUserIdentity::from_native_bytes(family, &user_native);
    let caller = ProcessIdentity::from_observation(
        time_domain,
        caller_first.pid,
        caller_first.start_time,
        user,
    );
    let terminal = match terminal {
        TerminalEvidence::Detached { second } => {
            if second.is_some() {
                return Err(ObservationError::ProcessChanged);
            }
            if caller_first.terminal_device.is_some() {
                return Err(ObservationError::TerminalBindingMismatch);
            }
            if caller_first.has_control_terminal {
                return Err(ObservationError::TerminalBindingMismatch);
            }
            if caller_first.terminal_session_id.is_some() {
                return Err(ObservationError::TerminalBindingMismatch);
            }
            None
        }
        TerminalEvidence::Attached {
            first,
            leader_first,
            leader_second,
            second,
        } => {
            if leader_first != leader_second || second != Some(first) {
                return Err(ObservationError::TerminalAnchorChanged);
            }
            if caller_first.terminal_device != Some(first.terminal_device)
                || caller_first.session_id != first.session_id
                || !caller_first.has_control_terminal
                || caller_first.terminal_session_id != Some(caller_first.session_id)
                || !first.device_binding_matches
                || leader_first.pid != caller_first.session_id
                || leader_first.process_group_id != caller_first.session_id
                || leader_first.session_id != caller_first.session_id
                || leader_first.terminal_device != Some(first.terminal_device)
                || !leader_first.has_control_terminal
                || leader_first.terminal_session_id != Some(caller_first.session_id)
                || !leader_first.is_session_leader
                || leader_first.effective_uid != caller_first.effective_uid
                || leader_first.user_namespace != caller_first.user_namespace
                || leader_first.start_time > caller_first.start_time
            {
                return Err(ObservationError::TerminalBindingMismatch);
            }

            let anchor = ProcessIdentity::from_observation(
                time_domain,
                leader_first.pid,
                leader_first.start_time,
                user,
            );
            let mut native = [0_u8; 12];
            native[0..8].copy_from_slice(&first.terminal_device.to_le_bytes());
            native[8..12].copy_from_slice(&first.session_id.get().to_le_bytes());
            let terminal = TerminalIdentity::from_native_bytes(family, &native);
            Some(TerminalSessionIdentity::from_observation(terminal, anchor))
        }
    };

    Ok(LocalSessionObservation::from_observation(
        caller,
        caller_first.parent_pid,
        terminal,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(
        pid: u32,
        parent_pid: u32,
        session_id: u32,
        terminal_device: Option<u64>,
        start_time: u64,
        effective_uid: u32,
    ) -> ProcessFacts {
        ProcessFacts {
            pid: NonZeroU32::new(pid).expect("nonzero test PID"),
            parent_pid: NonZeroU32::new(parent_pid),
            process_group_id: NonZeroU32::new(session_id).expect("nonzero test process group"),
            session_id: NonZeroU32::new(session_id).expect("nonzero test session"),
            terminal_device,
            terminal_session_id: terminal_device
                .map(|_| NonZeroU32::new(session_id).expect("nonzero test terminal session")),
            has_control_terminal: terminal_device.is_some(),
            is_session_leader: pid == session_id,
            start_time: NonZeroU64::new(start_time).expect("nonzero test start time"),
            effective_uid,
            user_namespace: 0,
        }
    }

    fn terminal() -> TerminalFacts {
        TerminalFacts {
            terminal_device: 30,
            session_id: NonZeroU32::new(9).expect("nonzero test session"),
            device_binding_matches: true,
        }
    }

    fn time_domain() -> ProcessTimeDomainIdentity {
        ProcessTimeDomainIdentity::from_native_bytes(
            PlatformFamily::MacOs,
            b"unix-timeval-microseconds-v1",
        )
    }

    #[test]
    fn attached_observation_binds_every_terminal_and_anchor_field() {
        let caller = process(42, 7, 9, Some(30), 200, 1000);
        let leader = process(9, 1, 9, Some(30), 100, 1000);
        let facts = terminal();
        let observation = assemble_observation(
            PlatformFamily::MacOs,
            time_domain(),
            caller,
            TerminalEvidence::Attached {
                first: facts,
                leader_first: leader,
                leader_second: leader,
                second: Some(facts),
            },
            caller,
        )
        .expect("valid BSD terminal observation");
        assert!(observation.has_terminal_session());
        assert_eq!(observation.caller().pid().get(), 42);
        assert_eq!(
            observation
                .terminal_session()
                .expect("terminal session")
                .anchor_process()
                .pid()
                .get(),
            9
        );
    }

    #[test]
    fn detached_observation_requires_stable_process_and_absent_tty() {
        let caller = process(42, 7, 42, None, 200, 1000);
        let observation = assemble_observation(
            PlatformFamily::FreeBsd,
            time_domain(),
            caller,
            TerminalEvidence::Detached { second: None },
            caller,
        )
        .expect("valid detached BSD observation");
        assert!(!observation.has_terminal_session());

        assert_eq!(
            assemble_observation(
                PlatformFamily::FreeBsd,
                time_domain(),
                caller,
                TerminalEvidence::Detached {
                    second: Some(terminal()),
                },
                caller,
            ),
            Err(ObservationError::ProcessChanged)
        );
    }

    #[test]
    fn caller_recheck_rejects_every_process_identity_mutation() {
        let caller = process(42, 7, 42, None, 200, 1000);
        let assert_changed = |mutate: fn(&mut ProcessFacts)| {
            let mut mutation = caller;
            mutate(&mut mutation);
            assert_eq!(
                assemble_observation(
                    PlatformFamily::MacOs,
                    time_domain(),
                    caller,
                    TerminalEvidence::Detached { second: None },
                    mutation,
                ),
                Err(ObservationError::ProcessChanged)
            );
        };
        assert_changed(|facts| facts.pid = NonZeroU32::new(43).expect("nonzero test PID"));
        assert_changed(|facts| facts.parent_pid = NonZeroU32::new(8));
        assert_changed(|facts| {
            facts.process_group_id = NonZeroU32::new(43).expect("nonzero test process group");
        });
        assert_changed(|facts| {
            facts.session_id = NonZeroU32::new(43).expect("nonzero test session");
        });
        assert_changed(|facts| facts.terminal_device = Some(30));
        assert_changed(|facts| {
            facts.terminal_session_id = NonZeroU32::new(43);
        });
        assert_changed(|facts| facts.has_control_terminal = true);
        assert_changed(|facts| facts.is_session_leader = false);
        assert_changed(|facts| {
            facts.start_time = NonZeroU64::new(201).expect("nonzero test start time");
        });
        assert_changed(|facts| facts.effective_uid = 1001);
        assert_changed(|facts| facts.user_namespace = 1);
    }

    #[test]
    fn attached_recheck_rejects_every_terminal_generation_mutation() {
        let caller = process(42, 7, 9, Some(30), 200, 1000);
        let leader = process(9, 1, 9, Some(30), 100, 1000);
        let first = terminal();
        let mut changed = first;
        let mut assert_changed = |mutate: fn(&mut TerminalFacts)| {
            changed = first;
            mutate(&mut changed);
            assert_eq!(
                assemble_observation(
                    PlatformFamily::MacOs,
                    time_domain(),
                    caller,
                    TerminalEvidence::Attached {
                        first,
                        leader_first: leader,
                        leader_second: leader,
                        second: Some(changed),
                    },
                    caller,
                ),
                Err(ObservationError::TerminalAnchorChanged)
            );
        };
        assert_changed(|facts| facts.terminal_device += 1);
        assert_changed(|facts| {
            facts.session_id = NonZeroU32::new(10).expect("nonzero test session");
        });
        assert_changed(|facts| facts.device_binding_matches = false);
    }

    #[test]
    fn stable_cross_binding_mismatches_are_rejected() {
        let caller = process(42, 7, 9, Some(30), 200, 1000);
        let facts = terminal();
        for leader in [
            process(10, 1, 9, Some(30), 100, 1000),
            process(9, 1, 10, Some(30), 100, 1000),
            process(9, 1, 9, Some(31), 100, 1000),
            process(9, 1, 9, Some(30), 100, 1001),
            process(9, 1, 9, Some(30), 201, 1000),
        ] {
            assert_eq!(
                assemble_observation(
                    PlatformFamily::MacOs,
                    time_domain(),
                    caller,
                    TerminalEvidence::Attached {
                        first: facts,
                        leader_first: leader,
                        leader_second: leader,
                        second: Some(facts),
                    },
                    caller,
                ),
                Err(ObservationError::TerminalBindingMismatch)
            );
        }
        let mut wrong_group = process(9, 1, 9, Some(30), 100, 1000);
        wrong_group.process_group_id = NonZeroU32::new(8).expect("nonzero test process group");
        assert_eq!(
            assemble_observation(
                PlatformFamily::MacOs,
                time_domain(),
                caller,
                TerminalEvidence::Attached {
                    first: facts,
                    leader_first: wrong_group,
                    leader_second: wrong_group,
                    second: Some(facts),
                },
                caller,
            ),
            Err(ObservationError::TerminalBindingMismatch)
        );

        let mut other_jail = process(9, 1, 9, Some(30), 100, 1000);
        other_jail.user_namespace = 2;
        assert_eq!(
            assemble_observation(
                PlatformFamily::FreeBsd,
                time_domain(),
                caller,
                TerminalEvidence::Attached {
                    first: facts,
                    leader_first: other_jail,
                    leader_second: other_jail,
                    second: Some(facts),
                },
                caller,
            ),
            Err(ObservationError::TerminalBindingMismatch)
        );
    }

    #[test]
    fn anchor_recheck_rejects_every_process_identity_mutation() {
        let caller = process(42, 7, 9, Some(30), 200, 1000);
        let leader = process(9, 1, 9, Some(30), 100, 1000);
        let terminal = terminal();
        let assert_changed = |mutate: fn(&mut ProcessFacts)| {
            let mut changed = leader;
            mutate(&mut changed);
            assert_eq!(
                assemble_observation(
                    PlatformFamily::FreeBsd,
                    time_domain(),
                    caller,
                    TerminalEvidence::Attached {
                        first: terminal,
                        leader_first: leader,
                        leader_second: changed,
                        second: Some(terminal),
                    },
                    caller,
                ),
                Err(ObservationError::TerminalAnchorChanged)
            );
        };
        assert_changed(|facts| facts.pid = NonZeroU32::new(10).expect("nonzero test PID"));
        assert_changed(|facts| facts.parent_pid = NonZeroU32::new(2));
        assert_changed(|facts| {
            facts.process_group_id = NonZeroU32::new(10).expect("nonzero test process group");
        });
        assert_changed(|facts| {
            facts.session_id = NonZeroU32::new(10).expect("nonzero test session");
        });
        assert_changed(|facts| facts.terminal_device = Some(31));
        assert_changed(|facts| {
            facts.terminal_session_id = NonZeroU32::new(10);
        });
        assert_changed(|facts| facts.has_control_terminal = false);
        assert_changed(|facts| facts.is_session_leader = false);
        assert_changed(|facts| {
            facts.start_time = NonZeroU64::new(101).expect("nonzero test start time");
        });
        assert_changed(|facts| facts.effective_uid = 1001);
        assert_changed(|facts| facts.user_namespace = 1);
    }

    #[test]
    fn timeval_conversion_rejects_sentinels_and_overflow() {
        let resource = ObservationResource::CallerProcess;
        assert_eq!(
            timeval_start(1, 2, resource),
            Ok(NonZeroU64::new(1_000_002).expect("nonzero start time"))
        );
        for (seconds, microseconds) in [(-1, 0), (1, -1), (1, 1_000_000), (0, 0), (i128::MAX, 0)] {
            assert_eq!(
                timeval_start(seconds, microseconds, resource),
                Err(ObservationError::Malformed { resource })
            );
        }
    }

    #[test]
    fn terminal_attachment_race_is_a_process_change() {
        let caller_first = process(42, 7, 42, None, 200, 1000);
        let mut caller_second = caller_first;
        caller_second.terminal_device = Some(30);
        caller_second.terminal_session_id = Some(caller_second.session_id);
        caller_second.has_control_terminal = true;
        let mut access = terminal();
        access.terminal_device = u64::MAX;
        access.device_binding_matches = false;
        let leader = process(42, 7, 42, Some(30), 200, 1000);
        assert_eq!(
            assemble_observation(
                PlatformFamily::FreeBsd,
                time_domain(),
                caller_first,
                TerminalEvidence::Attached {
                    first: access,
                    leader_first: leader,
                    leader_second: leader,
                    second: Some(access),
                },
                caller_second,
            ),
            Err(ObservationError::ProcessChanged)
        );
    }
}
