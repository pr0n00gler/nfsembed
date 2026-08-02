//! RFC 7530 sections 13.2 and 13.3 legal-error tables.
//!
//! Keeping these tables executable prevents an implementation path from
//! accidentally returning an error that is not legal for the discriminated
//! operation result on the wire.

use super::types::{CallbackOpNum, NfsStatus, OpNum};

/// Returns whether `status` is legal for an NFSv4.0 operation.
///
/// Unknown operation numbers are represented by the `ILLEGAL` result and
/// therefore use the `ILLEGAL` allowlist.
pub const fn is_legal_operation_status(opcode: u32, status: NfsStatus) -> bool {
    let operation = match OpNum::from_code(opcode) {
        Some(operation) => operation,
        None => OpNum::Illegal,
    };
    if matches!(status, NfsStatus::Ok) {
        return !matches!(operation, OpNum::Illegal);
    }

    match operation {
        OpNum::Access => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Close => matches!(
            status,
            NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::LocksHeld
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::OldStateId
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::Commit => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::Symlink
        ),
        OpNum::Create => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AttributeNotSupported
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadOwner
                | NfsStatus::BadType
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Exists
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::NotDirectory
                | NfsStatus::Permission
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::DelegPurge => matches!(
            status,
            NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::LeaseMoved
                | NfsStatus::NotSupported
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::StaleClientId
        ),
        OpNum::DelegReturn => matches!(
            status,
            NfsStatus::AdminRevoked
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Expired
                | NfsStatus::Invalid
                | NfsStatus::LeaseMoved
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NotSupported
                | NfsStatus::OldStateId
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::GetAttr => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::GetFh => matches!(
            status,
            NfsStatus::BadHandle
                | NfsStatus::FileHandleExpired
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Link => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Exists
                | NfsStatus::FileHandleExpired
                | NfsStatus::FileOpen
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::TooManyLinks
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::NotDirectory
                | NfsStatus::NotSupported
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::WrongSecurity
                | NfsStatus::CrossDevice
        ),
        OpNum::Lock => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadRange
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Deadlock
                | NfsStatus::Delay
                | NfsStatus::Denied
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::LockNotSupported
                | NfsStatus::LockRange
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NoGrace
                | NfsStatus::OldStateId
                | NfsStatus::OpenMode
                | NfsStatus::ReclaimBad
                | NfsStatus::ReclaimConflict
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleClientId
                | NfsStatus::StaleStateId
        ),
        OpNum::LockTest => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::BadRange
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Denied
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::LockRange
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleClientId
        ),
        OpNum::LockUnlock => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadRange
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::LockRange
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::OldStateId
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::Lookup => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NotDirectory
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::Symlink
                | NfsStatus::WrongSecurity
        ),
        OpNum::LookupParent => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NotDirectory
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::Symlink
                | NfsStatus::WrongSecurity
        ),
        OpNum::NotVerify => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AttributeNotSupported
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Same
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Open => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::AttributeNotSupported
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadOwner
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Exists
                | NfsStatus::Expired
                | NfsStatus::FileTooLarge
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                // RFC 7931 section 6.1.3 updates migration behavior:
                // OPEN is an implicit lease renewer and therefore reports
                // LEASE_MOVED despite RFC 7530 Table 9's omission.
                | NfsStatus::LeaseMoved
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NoGrace
                | NfsStatus::NoSpace
                | NfsStatus::NotDirectory
                | NfsStatus::NotSupported
                | NfsStatus::OldStateId
                | NfsStatus::Permission
                | NfsStatus::ReclaimBad
                | NfsStatus::ReclaimConflict
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::ShareDenied
                | NfsStatus::Stale
                | NfsStatus::StaleClientId
                | NfsStatus::Symlink
                | NfsStatus::WrongSecurity
        ),
        OpNum::OpenAttr => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::FileHandleExpired
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::NotSupported
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::OpenConfirm => matches!(
            status,
            NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::OldStateId
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::OpenDowngrade => matches!(
            status,
            NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadSequenceId
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::LeaseMoved
                | NfsStatus::LocksHeld
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::OldStateId
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::PutFh => matches!(
            status,
            NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Moved
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::WrongSecurity
        ),
        OpNum::PutPublicFh | OpNum::PutRootFh => {
            matches!(status, NfsStatus::Delay | NfsStatus::ServerFault | NfsStatus::WrongSecurity)
        },
        OpNum::Read => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Expired
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::Locked
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::OldStateId
                | NfsStatus::OpenMode
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
                | NfsStatus::Symlink
        ),
        OpNum::ReadDir => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCookie
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NotDirectory
                | NfsStatus::NotSame
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::TooSmall
        ),
        OpNum::ReadLink => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadHandle
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NotSupported
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Remove => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::FileOpen
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NotDirectory
                | NfsStatus::NotEmpty
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Rename => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Exists
                | NfsStatus::FileHandleExpired
                | NfsStatus::FileOpen
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::NotDirectory
                | NfsStatus::NotEmpty
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::WrongSecurity
                | NfsStatus::CrossDevice
        ),
        OpNum::Renew => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadXdr
                | NfsStatus::CallbackPathDown
                | NfsStatus::Expired
                | NfsStatus::LeaseMoved
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::StaleClientId
        ),
        OpNum::RestoreFh => matches!(
            status,
            NfsStatus::BadHandle
                | NfsStatus::FileHandleExpired
                | NfsStatus::Moved
                | NfsStatus::Resource
                | NfsStatus::RestoreFileHandle
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::WrongSecurity
        ),
        OpNum::SaveFh => matches!(
            status,
            NfsStatus::BadHandle
                | NfsStatus::FileHandleExpired
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::SecInfo => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadName
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Invalid
                | NfsStatus::Moved
                | NfsStatus::NameTooLong
                | NfsStatus::NotFound
                | NfsStatus::NoFileHandle
                | NfsStatus::NotDirectory
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::SetAttr => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::AttributeNotSupported
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadOwner
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Expired
                | NfsStatus::FileTooLarge
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::Locked
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::OldStateId
                | NfsStatus::OpenMode
                | NfsStatus::Permission
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
        ),
        OpNum::SetClientId => matches!(
            status,
            NfsStatus::BadXdr
                | NfsStatus::ClientIdInUse
                | NfsStatus::Delay
                | NfsStatus::Invalid
                | NfsStatus::Resource
                | NfsStatus::ServerFault
        ),
        OpNum::SetClientIdConfirm => matches!(
            status,
            NfsStatus::BadXdr
                | NfsStatus::ClientIdInUse
                | NfsStatus::Delay
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::StaleClientId
        ),
        OpNum::Verify => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AttributeNotSupported
                | NfsStatus::BadCharacter
                | NfsStatus::BadHandle
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NotSame
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::Stale
        ),
        OpNum::Write => matches!(
            status,
            NfsStatus::Access
                | NfsStatus::AdminRevoked
                | NfsStatus::BadHandle
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::Quota
                | NfsStatus::Expired
                | NfsStatus::FileTooLarge
                | NfsStatus::FileHandleExpired
                | NfsStatus::Grace
                | NfsStatus::Invalid
                | NfsStatus::Io
                | NfsStatus::IsDirectory
                | NfsStatus::LeaseMoved
                | NfsStatus::Locked
                | NfsStatus::Moved
                | NfsStatus::NoFileHandle
                | NfsStatus::NoSpace
                | NfsStatus::NoDeviceOrAddress
                | NfsStatus::OldStateId
                | NfsStatus::OpenMode
                | NfsStatus::Resource
                | NfsStatus::ReadOnly
                | NfsStatus::ServerFault
                | NfsStatus::Stale
                | NfsStatus::StaleStateId
                | NfsStatus::Symlink
        ),
        OpNum::ReleaseLockOwner => matches!(
            status,
            NfsStatus::BadXdr
                | NfsStatus::Expired
                | NfsStatus::LeaseMoved
                | NfsStatus::LocksHeld
                | NfsStatus::Resource
                | NfsStatus::ServerFault
                | NfsStatus::StaleClientId
        ),
        OpNum::Illegal => matches!(status, NfsStatus::BadXdr | NfsStatus::OperationIllegal),
    }
}

/// Returns whether `status` is legal for an NFSv4.0 callback operation.
pub const fn is_legal_callback_status(opcode: u32, status: NfsStatus) -> bool {
    let operation = match CallbackOpNum::from_code(opcode) {
        Some(operation) => operation,
        None => CallbackOpNum::Illegal,
    };
    if matches!(status, NfsStatus::Ok) {
        return !matches!(operation, CallbackOpNum::Illegal);
    }

    match operation {
        CallbackOpNum::GetAttr => matches!(
            status,
            NfsStatus::BadHandle | NfsStatus::BadXdr | NfsStatus::Delay | NfsStatus::Invalid | NfsStatus::ServerFault
        ),
        CallbackOpNum::Recall => matches!(
            status,
            NfsStatus::BadHandle
                | NfsStatus::BadStateId
                | NfsStatus::BadXdr
                | NfsStatus::Delay
                | NfsStatus::ServerFault
        ),
        CallbackOpNum::Illegal => matches!(status, NfsStatus::BadXdr | NfsStatus::OperationIllegal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_legal_except_for_illegal() {
        for opcode in 3..=39 {
            assert!(is_legal_operation_status(opcode, NfsStatus::Ok), "opcode {opcode}");
        }
        assert!(!is_legal_operation_status(OpNum::Illegal.code(), NfsStatus::Ok));
        assert!(!is_legal_operation_status(999, NfsStatus::Ok));
    }

    #[test]
    fn operation_specific_errors_do_not_leak_between_unions() {
        assert!(is_legal_operation_status(OpNum::Lock.code(), NfsStatus::Deadlock));
        assert!(!is_legal_operation_status(OpNum::Read.code(), NfsStatus::Deadlock));
        assert!(is_legal_operation_status(OpNum::ReadDir.code(), NfsStatus::TooSmall));
        assert!(!is_legal_operation_status(OpNum::GetAttr.code(), NfsStatus::TooSmall));
        assert!(is_legal_operation_status(OpNum::Illegal.code(), NfsStatus::OperationIllegal));
    }

    #[test]
    fn rfc7931_makes_lease_moved_legal_for_open() {
        assert!(is_legal_operation_status(OpNum::Open.code(), NfsStatus::LeaseMoved));
    }

    #[test]
    fn callback_table_is_distinct() {
        assert!(is_legal_callback_status(CallbackOpNum::Recall.code(), NfsStatus::BadStateId));
        assert!(!is_legal_callback_status(CallbackOpNum::GetAttr.code(), NfsStatus::BadStateId));
        assert!(is_legal_callback_status(99, NfsStatus::OperationIllegal));
    }
}
