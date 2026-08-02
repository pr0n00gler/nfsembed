use rand::RngCore;

use crate::nfs4::StateId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateKind {
    Open,
    ByteRangeLock,
    #[cfg_attr(not(test), allow(dead_code))]
    Delegation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateDisposition {
    Pending,
    Active,
    LeaseExpired,
    #[cfg_attr(not(test), allow(dead_code))]
    AdminRevoked,
    Closed,
}

#[derive(Clone, Debug)]
pub(crate) struct StateRecord<C, F, P> {
    pub client: C,
    pub file: F,
    pub kind: StateKind,
    pub payload: P,
    pub disposition: StateDisposition,
    sequence_id: u32,
    generation: u32,
}

impl<C, F, P> StateRecord<C, F, P> {
    pub fn stateid(&self, boot_tag: u32, index: u32) -> StateId {
        StateId {
            sequence_id: self.sequence_id,
            other: encode_other(boot_tag, index, self.generation),
        }
    }
}

#[derive(Debug)]
pub(crate) struct StateIdTable<C, F, P> {
    boot_tag: u32,
    capacity: usize,
    slots: Vec<StateSlot<C, F, P>>,
    free: Vec<usize>,
    active: usize,
}

#[derive(Debug)]
struct StateSlot<C, F, P> {
    record: Option<StateRecord<C, F, P>>,
    retired: Option<RetiredState>,
}

#[derive(Clone, Copy, Debug)]
struct RetiredState {
    generation: u32,
    disposition: StateDisposition,
}

impl<C, F, P> StateIdTable<C, F, P>
where
    F: Eq,
{
    #[allow(dead_code)]
    pub fn with_random_boot(capacity: usize) -> Result<Self, StateIdTableError> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(StateIdTableError::InvalidCapacity);
        }
        let mut random = rand::thread_rng();
        let mut boot_tag = random.next_u32();
        while boot_tag == 0 || boot_tag == u32::MAX {
            boot_tag = random.next_u32();
        }
        Ok(Self {
            boot_tag,
            capacity,
            slots: Vec::new(),
            free: Vec::new(),
            active: 0,
        })
    }

    pub fn with_boot_tag(capacity: usize, boot_tag: u32) -> Result<Self, StateIdTableError> {
        if capacity == 0 || capacity > u32::MAX as usize {
            return Err(StateIdTableError::InvalidCapacity);
        }
        if boot_tag == 0 || boot_tag == u32::MAX {
            return Err(StateIdTableError::InvalidBootTag);
        }
        Ok(Self {
            boot_tag,
            capacity,
            slots: Vec::new(),
            free: Vec::new(),
            active: 0,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn allocate(&mut self, client: C, file: F, kind: StateKind, payload: P) -> Result<StateId, StateIdTableError> {
        self.allocate_with_disposition(client, file, kind, payload, StateDisposition::Active)
    }

    pub fn allocate_pending(
        &mut self,
        client: C,
        file: F,
        kind: StateKind,
        payload: P,
    ) -> Result<StateId, StateIdTableError> {
        self.allocate_with_disposition(client, file, kind, payload, StateDisposition::Pending)
    }

    fn allocate_with_disposition(
        &mut self,
        client: C,
        file: F,
        kind: StateKind,
        payload: P,
        disposition: StateDisposition,
    ) -> Result<StateId, StateIdTableError> {
        if self.active >= self.capacity {
            return Err(StateIdTableError::Capacity);
        }
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                if self.slots.len() >= self.capacity || self.slots.len() >= u32::MAX as usize {
                    return Err(StateIdTableError::Capacity);
                }
                self.slots.push(StateSlot {
                    record: None,
                    retired: None,
                });
                self.slots.len() - 1
            },
        };
        let generation = self.slots[index]
            .retired
            .map_or(1, |retired| next_generation(retired.generation));
        let record = StateRecord {
            client,
            file,
            kind,
            payload,
            disposition,
            sequence_id: 1,
            generation,
        };
        let stateid = record.stateid(self.boot_tag, index as u32);
        self.slots[index].record = Some(record);
        self.active += 1;
        Ok(stateid)
    }

    pub fn activate(&mut self, stateid: StateId) -> Result<(), StateIdValidationError> {
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get_mut(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_mut() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation || record.disposition != StateDisposition::Pending {
            return Err(StateIdValidationError::BadStateId);
        }
        record.disposition = StateDisposition::Active;
        Ok(())
    }

    pub fn transition(&mut self, stateid: StateId) -> Result<StateId, StateIdValidationError> {
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get_mut(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_mut() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        validate_sequence(stateid.sequence_id, record.sequence_id)?;
        record.sequence_id = next_sequence_id(record.sequence_id);
        Ok(record.stateid(self.boot_tag, index as u32))
    }

    pub fn preview_transition(&self, stateid: StateId) -> Result<StateId, StateIdValidationError> {
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        validate_sequence(stateid.sequence_id, record.sequence_id)?;
        let mut next = record.stateid(self.boot_tag, index as u32);
        next.sequence_id = next_sequence_id(record.sequence_id);
        Ok(next)
    }

    /// Identifies a regular stateid without applying its sequence-id check.
    ///
    /// Stateful operation dispatch uses this only to locate the state-owner
    /// whose owner seqid has RFC-mandated priority over the stateid seqid.
    pub fn identify(&self, stateid: StateId) -> Result<&StateRecord<C, F, P>, StateIdValidationError> {
        if stateid.other == [0; 12] || stateid.other == [u8::MAX; 12] {
            return Err(StateIdValidationError::BadStateId);
        }
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        Ok(record)
    }

    pub fn identify_mut(&mut self, stateid: StateId) -> Result<&mut StateRecord<C, F, P>, StateIdValidationError> {
        if stateid.other == [0; 12] || stateid.other == [u8::MAX; 12] {
            return Err(StateIdValidationError::BadStateId);
        }
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get_mut(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_mut() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        Ok(record)
    }

    #[allow(dead_code)]
    pub fn current_stateid(&self, stateid: StateId) -> Result<StateId, StateIdValidationError> {
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        Ok(record.stateid(self.boot_tag, index as u32))
    }

    pub fn validate(
        &self,
        stateid: StateId,
        current_file: &F,
        accepted_kinds: &[StateKind],
    ) -> Result<StateIdValidation<'_, C, F, P>, StateIdValidationError> {
        if stateid.other == [0; 12] {
            return if stateid.sequence_id == 0 {
                Ok(StateIdValidation::Anonymous)
            } else {
                Err(StateIdValidationError::BadStateId)
            };
        }
        if stateid.other == [u8::MAX; 12] {
            return if stateid.sequence_id == u32::MAX {
                Ok(StateIdValidation::ReadBypass)
            } else {
                Err(StateIdValidationError::BadStateId)
            };
        }

        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation || &record.file != current_file || !accepted_kinds.contains(&record.kind) {
            return Err(if record.generation != generation {
                retired_error(slot.retired, generation)
            } else {
                StateIdValidationError::BadStateId
            });
        }
        if record.disposition != StateDisposition::Active {
            return Err(disposition_error(record.disposition));
        }
        validate_sequence(stateid.sequence_id, record.sequence_id)?;
        Ok(StateIdValidation::Active(record))
    }

    pub fn set_disposition(
        &mut self,
        stateid: StateId,
        disposition: StateDisposition,
    ) -> Result<(), StateIdValidationError> {
        let (index, generation) = self.decode_index(stateid)?;
        let slot = self.slots.get_mut(index).ok_or(StateIdValidationError::BadStateId)?;
        let Some(record) = slot.record.as_ref() else {
            return Err(retired_error(slot.retired, generation));
        };
        if record.generation != generation {
            return Err(retired_error(slot.retired, generation));
        }
        if matches!(
            disposition,
            StateDisposition::LeaseExpired | StateDisposition::AdminRevoked | StateDisposition::Closed
        ) {
            let retired = RetiredState {
                generation: record.generation,
                disposition,
            };
            slot.record = None;
            slot.retired = Some(retired);
            self.free.push(index);
            self.active = self.active.saturating_sub(1);
        } else {
            slot.record.as_mut().expect("record remains present").disposition = disposition;
        }
        Ok(())
    }

    pub fn boot_tag(&self) -> u32 {
        self.boot_tag
    }

    pub fn len(&self) -> usize {
        self.active
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn set_client_disposition(&mut self, client: &C, disposition: StateDisposition)
    where
        C: Eq,
    {
        let stateids = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let record = slot.record.as_ref()?;
                (&record.client == client
                    && matches!(record.disposition, StateDisposition::Active | StateDisposition::Pending))
                .then(|| record.stateid(self.boot_tag, index as u32))
            })
            .collect::<Vec<_>>();
        for stateid in stateids {
            self.set_disposition(stateid, disposition)
                .expect("stateid selected from this table remains valid");
        }
    }

    pub fn active_records_for_client<'a>(&'a self, client: &'a C) -> impl Iterator<Item = (StateId, &'a F, &'a P)> + 'a
    where
        C: Eq,
    {
        self.slots.iter().enumerate().filter_map(move |(index, slot)| {
            let record = slot.record.as_ref()?;
            (&record.client == client && record.disposition == StateDisposition::Active)
                .then(|| (record.stateid(self.boot_tag, index as u32), &record.file, &record.payload))
        })
    }

    fn decode_index(&self, stateid: StateId) -> Result<(usize, u32), StateIdValidationError> {
        let boot_tag = u32::from_be_bytes(stateid.other[0..4].try_into().expect("fixed stateid boot tag"));
        if boot_tag != self.boot_tag {
            return Err(StateIdValidationError::StaleStateId);
        }
        let index = u32::from_be_bytes(stateid.other[4..8].try_into().expect("fixed stateid index"));
        let generation = u32::from_be_bytes(stateid.other[8..12].try_into().expect("fixed stateid generation"));
        Ok((index as usize, generation))
    }
}

fn next_generation(generation: u32) -> u32 {
    generation.checked_add(1).filter(|generation| *generation != 0).unwrap_or(1)
}

fn retired_error(retired: Option<RetiredState>, generation: u32) -> StateIdValidationError {
    match retired.filter(|retired| retired.generation == generation) {
        Some(retired) => disposition_error(retired.disposition),
        None => StateIdValidationError::BadStateId,
    }
}

#[derive(Debug)]
pub(crate) enum StateIdValidation<'a, C, F, P> {
    Anonymous,
    ReadBypass,
    Active(&'a StateRecord<C, F, P>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StateIdTableError {
    #[error("stateid table capacity must fit a non-zero 32-bit index space")]
    InvalidCapacity,
    #[error("stateid boot tag must not use a reserved special-stateid value")]
    InvalidBootTag,
    #[error("stateid table capacity is exhausted")]
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StateIdValidationError {
    #[error("invalid stateid")]
    BadStateId,
    #[error("stateid belongs to an earlier server boot")]
    StaleStateId,
    #[error("stateid sequence is older than the current state")]
    OldStateId,
    #[error("state was lost after lease expiry")]
    Expired,
    #[error("state was administratively revoked")]
    AdminRevoked,
}

fn encode_other(boot_tag: u32, index: u32, generation: u32) -> [u8; 12] {
    let mut other = [0; 12];
    other[0..4].copy_from_slice(&boot_tag.to_be_bytes());
    other[4..8].copy_from_slice(&index.to_be_bytes());
    other[8..12].copy_from_slice(&generation.to_be_bytes());
    other
}

fn validate_sequence(provided: u32, current: u32) -> Result<(), StateIdValidationError> {
    if provided == 0 || provided == current {
        return Ok(());
    }
    if sequence_is_before(provided, current) {
        Err(StateIdValidationError::OldStateId)
    } else {
        Err(StateIdValidationError::BadStateId)
    }
}

fn sequence_is_before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32).is_negative()
}

fn next_sequence_id(current: u32) -> u32 {
    if current == u32::MAX {
        1
    } else {
        current + 1
    }
}

fn disposition_error(disposition: StateDisposition) -> StateIdValidationError {
    match disposition {
        StateDisposition::Pending => StateIdValidationError::BadStateId,
        StateDisposition::Active => StateIdValidationError::BadStateId,
        StateDisposition::LeaseExpired => StateIdValidationError::Expired,
        StateDisposition::AdminRevoked => StateIdValidationError::AdminRevoked,
        StateDisposition::Closed => StateIdValidationError::BadStateId,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> StateIdTable<u64, u64, &'static str> {
        StateIdTable::with_boot_tag(8, 0x1234_5678).unwrap()
    }

    #[test]
    fn allocates_first_stateid_at_sequence_one_and_advances() {
        let mut table = table();
        let stateid = table.allocate(7, 9, StateKind::Open, "open").unwrap();
        assert_eq!(stateid.sequence_id, 1);
        let next = table.transition(stateid).unwrap();
        assert_eq!(next.sequence_id, 2);
        assert_eq!(table.validate(stateid, &9, &[StateKind::Open]).unwrap_err(), StateIdValidationError::OldStateId);
        assert!(matches!(table.validate(next, &9, &[StateKind::Open]), Ok(StateIdValidation::Active(_))));
    }

    #[test]
    fn zero_sequence_selects_the_current_instance() {
        let mut table = table();
        let mut stateid = table.allocate(7, 9, StateKind::Open, "open").unwrap();
        stateid = table.transition(stateid).unwrap();
        stateid.sequence_id = 0;
        assert!(matches!(table.validate(stateid, &9, &[StateKind::Open]), Ok(StateIdValidation::Active(_))));
    }

    #[test]
    fn validates_only_the_two_defined_special_stateids() {
        let table = table();
        assert!(matches!(
            table.validate(
                StateId {
                    sequence_id: 0,
                    other: [0; 12],
                },
                &1,
                &[StateKind::Open]
            ),
            Ok(StateIdValidation::Anonymous)
        ));
        assert!(matches!(
            table.validate(
                StateId {
                    sequence_id: u32::MAX,
                    other: [u8::MAX; 12],
                },
                &1,
                &[StateKind::Open]
            ),
            Ok(StateIdValidation::ReadBypass)
        ));
        assert_eq!(
            table
                .validate(
                    StateId {
                        sequence_id: 1,
                        other: [0; 12],
                    },
                    &1,
                    &[StateKind::Open]
                )
                .unwrap_err(),
            StateIdValidationError::BadStateId
        );
    }

    #[test]
    fn distinguishes_stale_wrong_file_and_revoked_state() {
        let mut table = table();
        let stateid = table.allocate(7, 9, StateKind::Delegation, "delegation").unwrap();
        let mut stale = stateid;
        stale.other[0] ^= 1;
        assert_eq!(
            table.validate(stale, &9, &[StateKind::Delegation]).unwrap_err(),
            StateIdValidationError::StaleStateId
        );
        assert_eq!(
            table.validate(stateid, &8, &[StateKind::Delegation]).unwrap_err(),
            StateIdValidationError::BadStateId
        );
        table.set_disposition(stateid, StateDisposition::AdminRevoked).unwrap();
        assert_eq!(
            table.validate(stateid, &9, &[StateKind::Delegation]).unwrap_err(),
            StateIdValidationError::AdminRevoked
        );
    }

    #[test]
    fn retired_slots_are_reused_with_a_new_generation_and_a_bounded_tombstone() {
        let mut table = StateIdTable::with_boot_tag(1, 0x1234_5678).unwrap();
        let expired = table.allocate(7, 9, StateKind::Open, "first").unwrap();
        table.set_disposition(expired, StateDisposition::LeaseExpired).unwrap();
        assert_eq!(table.len(), 0);
        assert_eq!(table.validate(expired, &9, &[StateKind::Open]).unwrap_err(), StateIdValidationError::Expired);

        let replacement = table.allocate(8, 10, StateKind::Open, "second").unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(&replacement.other[..8], &expired.other[..8]);
        assert_ne!(&replacement.other[8..], &expired.other[8..]);
        assert!(matches!(table.validate(replacement, &10, &[StateKind::Open]), Ok(StateIdValidation::Active(_))));
        assert_eq!(table.validate(expired, &9, &[StateKind::Open]).unwrap_err(), StateIdValidationError::Expired);
    }
}
