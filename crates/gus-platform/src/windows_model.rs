use std::collections::{BTreeMap, BTreeSet};

const MAX_ANCESTRY_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessParent {
    pub(super) pid: u32,
    pub(super) parent_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorModelError {
    CallerMissing,
    CallerNotAttached,
    DuplicateProcess,
    MissingAttachedParent,
    AncestryCycle,
    AncestryDepth,
}

pub(super) fn derive_terminal_chain(
    caller_pid: u32,
    attached_processes: &[u32],
    process_snapshot: &[ProcessParent],
) -> Result<Vec<u32>, AnchorModelError> {
    let attached: BTreeSet<u32> = attached_processes.iter().copied().collect();
    if attached.len() != attached_processes.len() || attached.contains(&0) {
        return Err(AnchorModelError::DuplicateProcess);
    }
    if !attached.contains(&caller_pid) {
        return Err(AnchorModelError::CallerNotAttached);
    }

    let mut parents = BTreeMap::new();
    for process in process_snapshot {
        if process.pid == 0 || parents.insert(process.pid, process.parent_pid).is_some() {
            return Err(AnchorModelError::DuplicateProcess);
        }
    }
    if !parents.contains_key(&caller_pid) {
        return Err(AnchorModelError::CallerMissing);
    }

    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = caller_pid;
    loop {
        if chain.len() == MAX_ANCESTRY_DEPTH {
            return Err(AnchorModelError::AncestryDepth);
        }
        if !seen.insert(current) {
            return Err(AnchorModelError::AncestryCycle);
        }
        chain.push(current);
        let parent = *parents
            .get(&current)
            .ok_or(AnchorModelError::MissingAttachedParent)?;
        if parent == 0 || !attached.contains(&parent) {
            break;
        }
        if !parents.contains_key(&parent) {
            return Err(AnchorModelError::MissingAttachedParent);
        }
        current = parent;
    }
    Ok(chain)
}

pub(super) fn parent_of(
    caller_pid: u32,
    process_snapshot: &[ProcessParent],
) -> Result<u32, AnchorModelError> {
    let mut parent = None;
    for process in process_snapshot {
        if process.pid == caller_pid && parent.replace(process.parent_pid).is_some() {
            return Err(AnchorModelError::DuplicateProcess);
        }
    }
    parent.ok_or(AnchorModelError::CallerMissing)
}

pub(super) fn creation_order_is_valid(child_to_parent: &[u64]) -> bool {
    child_to_parent.windows(2).all(|pair| pair[1] <= pair[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent_pid: u32) -> ProcessParent {
        ProcessParent { pid, parent_pid }
    }

    #[test]
    fn terminal_chain_stops_at_the_highest_attached_ancestor() {
        let snapshot = [
            process(40, 30),
            process(30, 20),
            process(20, 10),
            process(10, 1),
        ];
        assert_eq!(
            derive_terminal_chain(40, &[20, 30, 40], &snapshot),
            Ok(vec![40, 30, 20])
        );
        assert_eq!(parent_of(40, &snapshot), Ok(30));
    }

    #[test]
    fn terminal_chain_rejects_missing_duplicate_and_cyclic_evidence() {
        assert_eq!(
            derive_terminal_chain(40, &[30], &[process(40, 30), process(30, 1)]),
            Err(AnchorModelError::CallerNotAttached)
        );
        assert_eq!(
            derive_terminal_chain(40, &[30, 40], &[process(40, 30)]),
            Err(AnchorModelError::MissingAttachedParent)
        );
        assert_eq!(
            derive_terminal_chain(40, &[30, 40], &[process(40, 30), process(30, 40)]),
            Err(AnchorModelError::AncestryCycle)
        );
        assert_eq!(
            derive_terminal_chain(40, &[30, 40, 40], &[process(40, 30), process(30, 1)]),
            Err(AnchorModelError::DuplicateProcess)
        );
        assert_eq!(
            parent_of(40, &[process(40, 30), process(40, 20)]),
            Err(AnchorModelError::DuplicateProcess)
        );
    }

    #[test]
    fn terminal_chain_has_a_hard_depth_bound() {
        let snapshot: Vec<ProcessParent> = (1..=257)
            .map(|pid| process(pid, pid.saturating_sub(1)))
            .collect();
        let attached: Vec<u32> = (1..=257).collect();
        assert_eq!(
            derive_terminal_chain(257, &attached, &snapshot),
            Err(AnchorModelError::AncestryDepth)
        );
    }

    #[test]
    fn creation_times_must_not_move_forward_toward_the_parent() {
        assert!(creation_order_is_valid(&[300, 200, 100]));
        assert!(creation_order_is_valid(&[300, 300, 100]));
        assert!(!creation_order_is_valid(&[200, 300, 100]));
    }
}
