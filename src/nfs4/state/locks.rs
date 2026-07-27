use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockRange {
    pub start: u64,
    /// Exclusive end; `None` denotes a range extending through EOF.
    pub end: Option<u64>,
}

impl LockRange {
    pub fn from_offset_length(offset: u64, length: u64) -> Result<Self, LockRangeError> {
        if length == 0 {
            return Err(LockRangeError::Empty);
        }
        if length == u64::MAX {
            return Ok(Self {
                start: offset,
                end: None,
            });
        }
        let end = offset.checked_add(length).ok_or(LockRangeError::Overflow)?;
        Ok(Self {
            start: offset,
            end: Some(end),
        })
    }

    fn overlaps(self, other: Self) -> bool {
        end_gt(self.end, other.start) && end_gt(other.end, self.start)
    }

    fn adjacent_or_overlapping(self, other: Self) -> bool {
        self.overlaps(other) || self.end == Some(other.start) || other.end == Some(self.start)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum LockRangeError {
    #[error("lock range length is zero")]
    Empty,
    #[error("lock range overflows the 64-bit file offset space")]
    Overflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockRecord<O, I> {
    pub owner: O,
    /// Identity of the OPEN state from which this lock state originated.
    pub open: I,
    pub access: LockAccess,
    pub range: LockRange,
}

#[derive(Clone, Debug)]
pub(crate) struct LockTable<O, I> {
    records: Vec<LockRecord<O, I>>,
}

impl<O, I> Default for LockTable<O, I> {
    fn default() -> Self {
        Self { records: Vec::new() }
    }
}

impl<O, I> LockTable<O, I>
where
    O: Clone + Eq,
    I: Clone + Eq,
{
    pub fn records(&self) -> &[LockRecord<O, I>] {
        &self.records
    }

    pub fn conflict(&self, owner: &O, access: LockAccess, range: LockRange) -> Option<&LockRecord<O, I>> {
        self.conflict_excluding(|candidate| candidate == owner, access, range)
    }

    #[cfg(test)]
    pub fn conflict_any(&self, access: LockAccess, range: LockRange) -> Option<&LockRecord<O, I>> {
        self.conflict_excluding(|_| false, access, range)
    }

    pub fn conflict_excluding(
        &self,
        mut excluded: impl FnMut(&O) -> bool,
        access: LockAccess,
        range: LockRange,
    ) -> Option<&LockRecord<O, I>> {
        self.records.iter().find(|record| {
            !excluded(&record.owner)
                && record.range.overlaps(range)
                && (record.access == LockAccess::Write || access == LockAccess::Write)
        })
    }

    pub fn lock(&mut self, owner: O, open: I, access: LockAccess, range: LockRange) -> Result<(), LockRecord<O, I>> {
        if let Some(conflict) = self.conflict(&owner, access, range) {
            return Err(conflict.clone());
        }

        self.remove_owner_range(&owner, range);
        let normalized_owner = owner.clone();
        self.records.push(LockRecord {
            owner,
            open,
            access,
            range,
        });
        self.normalize_owner(&normalized_owner);
        Ok(())
    }

    /// Removes the specified portion of this owner's locks.
    pub fn unlock(&mut self, owner: &O, range: LockRange) -> bool {
        let before = self.records.clone();
        self.remove_owner_range(owner, range);
        let changed = before != self.records;
        if changed {
            self.normalize_owner(owner);
        }
        changed
    }

    #[allow(dead_code)]
    pub fn release_owner(&mut self, owner: &O) {
        self.records.retain(|record| &record.owner != owner);
    }

    pub fn release_where(&mut self, mut predicate: impl FnMut(&O) -> bool) {
        self.records.retain(|record| !predicate(&record.owner));
    }

    pub fn has_open(&self, open: &I) -> bool {
        self.records.iter().any(|record| &record.open == open)
    }

    pub fn open_requires(&self, open: &I, access: LockAccess) -> bool {
        self.records
            .iter()
            .any(|record| &record.open == open && record.access == access)
    }

    fn remove_owner_range(&mut self, owner: &O, removed: LockRange) {
        let mut replacement = Vec::with_capacity(self.records.len().saturating_add(1));
        for record in self.records.drain(..) {
            if &record.owner != owner || !record.range.overlaps(removed) {
                replacement.push(record);
                continue;
            }

            if record.range.start < removed.start {
                replacement.push(LockRecord {
                    owner: record.owner.clone(),
                    open: record.open.clone(),
                    access: record.access,
                    range: LockRange {
                        start: record.range.start,
                        end: Some(removed.start),
                    },
                });
            }

            if let Some(removed_end) = removed.end {
                if end_gt(record.range.end, removed_end) {
                    replacement.push(LockRecord {
                        owner: record.owner,
                        open: record.open,
                        access: record.access,
                        range: LockRange {
                            start: removed_end,
                            end: record.range.end,
                        },
                    });
                }
            }
        }
        self.records = replacement;
    }

    fn normalize_owner(&mut self, owner: &O) {
        let mut owner_records = Vec::new();
        let mut other_records = Vec::with_capacity(self.records.len());
        for record in self.records.drain(..) {
            if &record.owner == owner {
                owner_records.push(record);
            } else {
                other_records.push(record);
            }
        }
        owner_records.sort_by(|left, right| {
            left.range
                .start
                .cmp(&right.range.start)
                .then_with(|| compare_end(left.range.end, right.range.end))
        });
        let mut normalized = Vec::<LockRecord<O, I>>::with_capacity(owner_records.len());
        for record in owner_records {
            if let Some(previous) = normalized.last_mut() {
                if previous.open == record.open
                    && previous.access == record.access
                    && previous.range.adjacent_or_overlapping(record.range)
                {
                    previous.range.end = max_end(previous.range.end, record.range.end);
                    continue;
                }
            }
            normalized.push(record);
        }
        other_records.extend(normalized);
        other_records.sort_by(|left, right| {
            left.range
                .start
                .cmp(&right.range.start)
                .then_with(|| compare_end(left.range.end, right.range.end))
        });
        self.records = other_records;
    }
}

fn end_gt(end: Option<u64>, value: u64) -> bool {
    end.is_none_or(|end| end > value)
}

fn compare_end(left: Option<u64>, right: Option<u64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn max_end(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, length: u64) -> LockRange {
        LockRange::from_offset_length(start, length).unwrap()
    }

    #[test]
    fn rejects_empty_and_overflowing_ranges() {
        assert_eq!(LockRange::from_offset_length(1, 0), Err(LockRangeError::Empty));
        assert_eq!(LockRange::from_offset_length(u64::MAX - 1, 2), Err(LockRangeError::Overflow));
    }

    #[test]
    fn read_locks_coexist_but_write_conflicts() {
        let mut locks = LockTable::default();
        locks.lock(1u64, 10u64, LockAccess::Read, range(0, 100)).unwrap();
        locks.lock(2u64, 20u64, LockAccess::Read, range(50, 100)).unwrap();
        let conflict = locks.lock(3u64, 30u64, LockAccess::Write, range(75, 1)).unwrap_err();
        assert_eq!(conflict.owner, 1);
    }

    #[test]
    fn same_owner_upgrade_splits_and_replaces_ranges() {
        let mut locks = LockTable::default();
        locks.lock(1u64, 10u64, LockAccess::Read, range(0, 100)).unwrap();
        locks.lock(1u64, 10u64, LockAccess::Write, range(25, 50)).unwrap();
        assert_eq!(
            locks.records(),
            &[
                LockRecord {
                    owner: 1,
                    open: 10,
                    access: LockAccess::Read,
                    range: range(0, 25),
                },
                LockRecord {
                    owner: 1,
                    open: 10,
                    access: LockAccess::Write,
                    range: range(25, 50),
                },
                LockRecord {
                    owner: 1,
                    open: 10,
                    access: LockAccess::Read,
                    range: range(75, 25),
                },
            ]
        );
    }

    #[test]
    fn unlock_subrange_preserves_both_sides() {
        let mut locks = LockTable::default();
        locks.lock(9u64, 90u64, LockAccess::Write, range(0, 100)).unwrap();
        assert!(locks.unlock(&9, range(40, 20)));
        assert_eq!(locks.records().len(), 2);
        assert_eq!(locks.records()[0].range, range(0, 40));
        assert_eq!(locks.records()[1].range, range(60, 40));
        assert!(locks.records().iter().all(|record| record.open == 90));
    }

    #[test]
    fn eof_range_conflicts_at_arbitrary_later_offset() {
        let mut locks = LockTable::default();
        let through_eof = LockRange::from_offset_length(100, u64::MAX).unwrap();
        locks.lock(1u64, 10u64, LockAccess::Write, through_eof).unwrap();
        assert!(locks.conflict(&2, LockAccess::Read, range(10_000, 1)).is_some());
        assert!(locks.conflict(&2, LockAccess::Read, range(0, 100)).is_none());
    }

    #[test]
    fn records_retain_their_originating_open() {
        let mut locks = LockTable::default();
        locks.lock(1u64, 10u64, LockAccess::Read, range(0, 10)).unwrap();
        locks.lock(2u64, 20u64, LockAccess::Read, range(20, 10)).unwrap();

        assert!(locks.has_open(&10));
        assert!(locks.open_requires(&10, LockAccess::Read));
        assert!(!locks.open_requires(&10, LockAccess::Write));
        assert!(locks.has_open(&20));
    }

    #[test]
    fn exact_owner_io_exclusion_does_not_exclude_every_lock_from_one_open() {
        let mut locks = LockTable::default();
        locks.lock((1u64, 10u64), 10u64, LockAccess::Write, range(0, 10)).unwrap();
        locks.lock((2u64, 10u64), 10u64, LockAccess::Write, range(20, 10)).unwrap();

        assert!(locks.conflict(&(1, 10), LockAccess::Write, range(0, 10)).is_none());
        assert!(locks.conflict(&(1, 10), LockAccess::Write, range(20, 10)).is_some());
        assert!(locks.conflict_any(LockAccess::Write, range(0, 10)).is_some());
    }

    #[test]
    fn composite_owners_keep_same_protocol_owner_scopes_independent() {
        let mut locks = LockTable::default();
        locks.lock((1u64, 10u64), 10u64, LockAccess::Read, range(0, 10)).unwrap();
        locks.lock((1u64, 20u64), 20u64, LockAccess::Read, range(10, 10)).unwrap();

        assert_eq!(locks.records().len(), 2, "different OPEN identities must not merge");
        assert!(locks.unlock(&(1, 10), range(0, 20)));
        assert_eq!(locks.records().len(), 1, "unlock must affect only the exact composite owner");
        assert_eq!(locks.records()[0].owner, (1, 20));
    }

    #[test]
    fn normalization_merges_one_owners_ranges_across_interleaved_read_locks() {
        let mut locks = LockTable::default();
        locks.lock(1u64, 10u64, LockAccess::Read, range(0, 100)).unwrap();
        locks.lock(2u64, 20u64, LockAccess::Read, range(25, 50)).unwrap();
        locks.lock(1u64, 10u64, LockAccess::Read, range(100, 50)).unwrap();

        let owner_ranges = locks
            .records()
            .iter()
            .filter(|record| record.owner == 1)
            .map(|record| record.range)
            .collect::<Vec<_>>();
        assert_eq!(owner_ranges, vec![range(0, 150)]);
    }
}
