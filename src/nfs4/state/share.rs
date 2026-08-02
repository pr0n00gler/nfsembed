#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareAccess(u32);

impl ShareAccess {
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    #[cfg_attr(not(test), allow(dead_code))]
    pub const BOTH: Self = Self(0x3);

    pub fn from_wire(value: u32) -> Option<Self> {
        matches!(value, 1..=3).then_some(Self(value))
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareDeny(u32);

impl ShareDeny {
    #[cfg_attr(not(test), allow(dead_code))]
    pub const NONE: Self = Self(0);
    #[cfg_attr(not(test), allow(dead_code))]
    pub const READ: Self = Self(0x1);
    #[cfg_attr(not(test), allow(dead_code))]
    pub const WRITE: Self = Self(0x2);
    #[cfg_attr(not(test), allow(dead_code))]
    pub const BOTH: Self = Self(0x3);

    pub fn from_wire(value: u32) -> Option<Self> {
        matches!(value, 0..=3).then_some(Self(value))
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShareReservation<O> {
    pub owner: O,
    pub access: ShareAccess,
    pub deny: ShareDeny,
    contributions: ShareContributions,
}

const SHARE_ACCESS_VARIANTS: usize = 3;
const SHARE_DENY_VARIANTS: usize = 4;
const SHARE_CONTRIBUTION_VARIANTS: usize = SHARE_ACCESS_VARIANTS * SHARE_DENY_VARIANTS;

/// A bounded, order-independent multiset of the OPEN requests represented by
/// one share reservation.
///
/// There are only twelve legal `(share_access, share_deny)` pairs on the wire,
/// so fixed counters preserve exact multiplicity without allowing a client to
/// grow a `Vec` with every repeated OPEN.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ShareContributions {
    counts: [u32; SHARE_CONTRIBUTION_VARIANTS],
}

impl ShareContributions {
    pub fn single(access: ShareAccess, deny: ShareDeny) -> Self {
        let mut contributions = Self::default();
        contributions.counts[contribution_index(access, deny)] = 1;
        contributions
    }

    pub fn add(
        &mut self,
        access: ShareAccess,
        deny: ShareDeny,
        count: u32,
        maximum: usize,
    ) -> Result<(), ShareContributionLimit> {
        if count == 0 {
            return Err(ShareContributionLimit);
        }
        let count = usize::try_from(count).map_err(|_| ShareContributionLimit)?;
        if self.total().checked_add(count).is_none_or(|total| total > maximum) {
            return Err(ShareContributionLimit);
        }
        let index = contribution_index(access, deny);
        self.counts[index] = self.counts[index]
            .checked_add(u32::try_from(count).map_err(|_| ShareContributionLimit)?)
            .ok_or(ShareContributionLimit)?;
        Ok(())
    }

    pub fn total(self) -> usize {
        self.counts
            .into_iter()
            .fold(0usize, |total, count| total.saturating_add(count as usize))
    }

    pub fn entries(self) -> impl Iterator<Item = (ShareAccess, ShareDeny, u32)> {
        self.counts
            .into_iter()
            .enumerate()
            .filter(|(_, count)| *count != 0)
            .map(|(index, count)| {
                let access = ShareAccess((index / SHARE_DENY_VARIANTS + 1) as u32);
                let deny = ShareDeny((index % SHARE_DENY_VARIANTS) as u32);
                (access, deny, count)
            })
    }

    fn retained(self, access: ShareAccess, deny: ShareDeny) -> Self {
        let mut retained = Self::default();
        for (contribution_access, contribution_deny, count) in self.entries() {
            if access.contains(contribution_access) && deny.contains(contribution_deny) {
                retained.counts[contribution_index(contribution_access, contribution_deny)] = count;
            }
        }
        retained
    }

    pub fn aggregate(self) -> Option<(ShareAccess, ShareDeny)> {
        let mut entries = self.entries();
        let (access, deny, _) = entries.next()?;
        Some(entries.fold((access, deny), |(access, deny), (next_access, next_deny, _)| {
            (access.union(next_access), deny.union(next_deny))
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("share contribution limit exceeded")]
pub(crate) struct ShareContributionLimit;

fn contribution_index(access: ShareAccess, deny: ShareDeny) -> usize {
    debug_assert!((1..=3).contains(&access.bits()));
    debug_assert!(deny.bits() <= 3);
    (access.bits() as usize - 1) * SHARE_DENY_VARIANTS + deny.bits() as usize
}

#[derive(Clone, Debug)]
pub(crate) struct ShareTable<O> {
    reservations: Vec<ShareReservation<O>>,
}

impl<O> Default for ShareTable<O> {
    fn default() -> Self {
        Self {
            reservations: Vec::new(),
        }
    }
}

impl<O> ShareTable<O>
where
    O: Clone + Eq,
{
    pub fn reservations(&self) -> &[ShareReservation<O>] {
        &self.reservations
    }

    /// Creates a reservation or atomically upgrades an existing reservation
    /// owned by the same open-owner.
    pub fn open(
        &mut self,
        owner: O,
        access: ShareAccess,
        deny: ShareDeny,
        maximum_contributions: usize,
    ) -> Result<ShareReservation<O>, ShareOpenError<O>> {
        // A share reservation constrains every later OPEN, including one
        // issued by the same open-owner.  Owner identity controls how
        // successful contributions are combined; it does not exempt a new
        // request from an already granted deny mode.
        if let Some(conflict) = self
            .reservations
            .iter()
            .find(|entry| access.bits() & entry.deny.bits() != 0 || entry.access.bits() & deny.bits() != 0)
        {
            return Err(ShareOpenError::Conflict(ShareConflict {
                owner: conflict.owner.clone(),
                access: conflict.access,
                deny: conflict.deny,
            }));
        }
        let contributions = match self.reservations.iter().find(|entry| entry.owner == owner) {
            Some(entry) => {
                let mut contributions = entry.contributions;
                contributions
                    .add(access, deny, 1, maximum_contributions)
                    .map_err(|_| ShareOpenError::ContributionLimit)?;
                contributions
            },
            None if maximum_contributions != 0 => ShareContributions::single(access, deny),
            None => return Err(ShareOpenError::ContributionLimit),
        };
        self.install(owner, contributions, maximum_contributions)
    }

    /// Installs an already-planned contribution multiset.
    ///
    /// Recovery uses this to restore the exact pre-restart OPEN history rather
    /// than treating the reclaim request itself as the only contribution.
    pub fn install(
        &mut self,
        owner: O,
        contributions: ShareContributions,
        maximum_contributions: usize,
    ) -> Result<ShareReservation<O>, ShareOpenError<O>> {
        if contributions.total() == 0 || contributions.total() > maximum_contributions {
            return Err(ShareOpenError::ContributionLimit);
        }
        let (candidate_access, candidate_deny) = contributions.aggregate().ok_or(ShareOpenError::ContributionLimit)?;
        if let Some(conflict) = self.reservations.iter().find(|entry| {
            entry.owner != owner
                && (candidate_access.bits() & entry.deny.bits() != 0
                    || entry.access.bits() & candidate_deny.bits() != 0)
        }) {
            return Err(ShareOpenError::Conflict(ShareConflict {
                owner: conflict.owner.clone(),
                access: conflict.access,
                deny: conflict.deny,
            }));
        }

        let reservation = ShareReservation {
            owner,
            access: candidate_access,
            deny: candidate_deny,
            contributions,
        };
        if let Some(existing) = self.reservations.iter_mut().find(|entry| entry.owner == reservation.owner) {
            *existing = reservation.clone();
        } else {
            self.reservations.push(reservation.clone());
        }
        Ok(reservation)
    }

    pub fn downgrade(
        &mut self,
        owner: &O,
        access: ShareAccess,
        deny: ShareDeny,
    ) -> Result<ShareReservation<O>, ShareDowngradeError> {
        let reservation = self
            .reservations
            .iter_mut()
            .find(|entry| &entry.owner == owner)
            .ok_or(ShareDowngradeError::MissingReservation)?;
        if !reservation.access.contains(access) || !reservation.deny.contains(deny) {
            return Err(ShareDowngradeError::AddsBits);
        }

        // OPEN_DOWNGRADE does not merely accept an arbitrary bitwise
        // subset.  RFC 7530 requires the requested pair to be the union
        // of some subset of the OPEN requests still in effect.  Keeping
        // every compatible contribution gives a deterministic maximal
        // subset and preserves duplicate OPEN counts for later
        // downgrades.
        let retained = reservation.contributions.retained(access, deny);
        let Some((retained_access, retained_deny)) = retained.aggregate() else {
            return Err(ShareDowngradeError::InvalidContributionSubset);
        };
        if retained_access != access || retained_deny != deny {
            return Err(ShareDowngradeError::InvalidContributionSubset);
        }

        reservation.contributions = retained;
        reservation.access = access;
        reservation.deny = deny;
        Ok(reservation.clone())
    }

    pub fn close(&mut self, owner: &O) -> bool {
        let previous = self.reservations.len();
        self.reservations.retain(|entry| &entry.owner != owner);
        previous != self.reservations.len()
    }

    pub fn release_where(&mut self, mut predicate: impl FnMut(&O) -> bool) {
        self.reservations.retain(|reservation| !predicate(&reservation.owner));
    }

    pub fn conflicts_with_access(&self, access: ShareAccess) -> bool {
        self.reservations
            .iter()
            .any(|reservation| access.bits() & reservation.deny.bits() != 0)
    }

    #[allow(dead_code)]
    pub fn conflicts_with_deny(&self, deny: ShareDeny) -> bool {
        self.reservations
            .iter()
            .any(|reservation| reservation.access.bits() & deny.bits() != 0)
    }
}

impl<O> ShareReservation<O> {
    pub fn contributions(&self) -> ShareContributions {
        self.contributions
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ShareOpenError<O> {
    #[error("share reservation conflicts with another owner")]
    Conflict(ShareConflict<O>),
    #[error("share contribution limit exceeded")]
    ContributionLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShareConflict<O> {
    pub owner: O,
    pub access: ShareAccess,
    pub deny: ShareDeny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ShareDowngradeError {
    #[error("open-owner has no share reservation")]
    MissingReservation,
    #[error("OPEN_DOWNGRADE would add access or deny bits")]
    AddsBits,
    #[error("OPEN_DOWNGRADE is not the union of a subset of OPEN contributions")]
    InvalidContributionSubset,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 16;

    #[test]
    fn share_conflict_matrix_is_symmetric() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::READ, ShareDeny::WRITE, LIMIT).unwrap();
        assert!(shares.open(2, ShareAccess::READ, ShareDeny::NONE, LIMIT).is_ok());
        assert!(shares.open(3, ShareAccess::WRITE, ShareDeny::NONE, LIMIT).is_err());

        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::WRITE, ShareDeny::NONE, LIMIT).unwrap();
        assert!(shares.open(2, ShareAccess::READ, ShareDeny::WRITE, LIMIT).is_err());
    }

    #[test]
    fn same_owner_open_upgrades_existing_reservation() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::READ, ShareDeny::NONE, LIMIT).unwrap();
        let upgraded = shares.open(1, ShareAccess::WRITE, ShareDeny::NONE, LIMIT).unwrap();
        assert_eq!(upgraded.access, ShareAccess::BOTH);
        assert_eq!(upgraded.deny, ShareDeny::NONE);
        assert_eq!(shares.reservations().len(), 1);
    }

    #[test]
    fn same_owner_is_still_subject_to_existing_share_denies() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::BOTH, ShareDeny::READ, LIMIT).unwrap();
        assert!(matches!(
            shares.open(1, ShareAccess::READ, ShareDeny::NONE, LIMIT),
            Err(ShareOpenError::Conflict(_))
        ));

        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::BOTH, ShareDeny::WRITE, LIMIT).unwrap();
        assert!(matches!(
            shares.open(1, ShareAccess::WRITE, ShareDeny::NONE, LIMIT),
            Err(ShareOpenError::Conflict(_))
        ));
    }

    #[test]
    fn downgrade_must_be_a_subset() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::BOTH, ShareDeny::BOTH, LIMIT).unwrap();
        assert_eq!(
            shares.downgrade(&1, ShareAccess::READ, ShareDeny::NONE),
            Err(ShareDowngradeError::InvalidContributionSubset)
        );
    }

    #[test]
    fn downgrade_must_equal_the_union_of_actual_open_contributions() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::READ, ShareDeny::NONE, LIMIT).unwrap();
        shares.open(1, ShareAccess::WRITE, ShareDeny::NONE, LIMIT).unwrap();

        let downgraded = shares.downgrade(&1, ShareAccess::READ, ShareDeny::NONE).unwrap();
        assert_eq!(downgraded.access, ShareAccess::READ);
        assert_eq!(downgraded.deny, ShareDeny::NONE);

        // The WRITE contribution was removed by the first downgrade, so it
        // cannot be resurrected by a later request.
        assert_eq!(shares.downgrade(&1, ShareAccess::WRITE, ShareDeny::NONE), Err(ShareDowngradeError::AddsBits));
    }

    #[test]
    fn duplicate_open_contributions_are_preserved() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::READ, ShareDeny::NONE, LIMIT).unwrap();
        shares.open(1, ShareAccess::READ, ShareDeny::NONE, LIMIT).unwrap();
        shares.open(1, ShareAccess::WRITE, ShareDeny::NONE, LIMIT).unwrap();

        assert!(shares.downgrade(&1, ShareAccess::READ, ShareDeny::NONE).is_ok());
        let reservation = &shares.reservations()[0];
        assert_eq!(reservation.contributions.total(), 2);
    }

    #[test]
    fn repeated_open_contributions_are_bounded_without_losing_counts() {
        let mut shares = ShareTable::default();
        shares.open(1u64, ShareAccess::READ, ShareDeny::NONE, 2).unwrap();
        shares.open(1, ShareAccess::READ, ShareDeny::NONE, 2).unwrap();
        assert_eq!(shares.open(1, ShareAccess::READ, ShareDeny::NONE, 2), Err(ShareOpenError::ContributionLimit));
        let contributions = shares.reservations()[0].contributions();
        assert_eq!(contributions.total(), 2);
        assert_eq!(contributions.entries().collect::<Vec<_>>(), vec![(ShareAccess::READ, ShareDeny::NONE, 2)]);
    }
}
