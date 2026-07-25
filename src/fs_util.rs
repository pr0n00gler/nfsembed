use std::fs::Metadata;
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs::OpenOptions;
use tracing::debug;

use crate::nfs::*;

/// Compares whether file metadata changed in a way visible through NFS.
pub fn metadata_differ(lhs: &Metadata, rhs: &Metadata) -> bool {
    let lhs_modified = metadata_modified(lhs);
    let rhs_modified = metadata_modified(rhs);
    metadata_identity(lhs) != metadata_identity(rhs)
        || lhs_modified.seconds != rhs_modified.seconds
        || lhs_modified.nseconds != rhs_modified.nseconds
        || lhs.len() != rhs.len()
        || lhs.file_type() != rhs.file_type()
}

pub fn fattr3_differ(lhs: &fattr3, rhs: &fattr3) -> bool {
    lhs.fileid != rhs.fileid
        || lhs.mtime.seconds != rhs.mtime.seconds
        || lhs.mtime.nseconds != rhs.mtime.nseconds
        || lhs.size != rhs.size
        || lhs.ftype as u32 != rhs.ftype as u32
}

/// Checks existence without following a final symlink.
pub fn exists_no_traverse(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

fn nfs_time(time: SystemTime) -> nfstime3 {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    nfstime3 {
        seconds: u32::try_from(duration.as_secs()).unwrap_or(u32::MAX),
        nseconds: duration.subsec_nanos(),
    }
}

fn metadata_accessed(meta: &Metadata) -> nfstime3 {
    nfs_time(meta.accessed().unwrap_or(UNIX_EPOCH))
}

fn metadata_modified(meta: &Metadata) -> nfstime3 {
    nfs_time(meta.modified().unwrap_or(UNIX_EPOCH))
}

#[cfg(unix)]
fn metadata_changed(meta: &Metadata) -> nfstime3 {
    nfstime3 {
        seconds: u32::try_from(meta.ctime().max(0)).unwrap_or(u32::MAX),
        nseconds: u32::try_from(meta.ctime_nsec().clamp(0, 999_999_999)).unwrap_or_default(),
    }
}

#[cfg(windows)]
fn metadata_changed(meta: &Metadata) -> nfstime3 {
    nfs_time(meta.modified().or_else(|_| meta.created()).unwrap_or(UNIX_EPOCH))
}

#[cfg(unix)]
fn metadata_identity(meta: &Metadata) -> u64 {
    meta.ino()
}

#[cfg(windows)]
fn metadata_identity(_meta: &Metadata) -> u64 {
    // The legacy VFS supplies its own file id. std does not expose a stable
    // cross-volume identity on every supported Windows Rust toolchain.
    0
}

#[cfg(unix)]
fn metadata_mode(meta: &Metadata) -> u32 {
    (meta.mode() | 0o200) & 0o777
}

#[cfg(windows)]
fn metadata_mode(meta: &Metadata) -> u32 {
    let base = if meta.is_dir() { 0o555 } else { 0o444 };
    if meta.permissions().readonly() {
        base
    } else {
        base | 0o222
    }
}

#[cfg(unix)]
fn metadata_owner(meta: &Metadata) -> (u32, u32) {
    (meta.uid(), meta.gid())
}

#[cfg(windows)]
fn metadata_owner(_meta: &Metadata) -> (u32, u32) {
    (0, 0)
}

#[cfg(unix)]
fn set_path_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, Permissions::from_mode((mode | 0o200) & 0o777))
}

#[cfg(windows)]
fn set_path_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions)
}

#[cfg(unix)]
fn set_file_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    file.set_permissions(Permissions::from_mode((mode | 0o200) & 0o777))
}

#[cfg(windows)]
fn set_file_mode(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions)
}

fn io_error_to_nfs(error: std::io::Error) -> nfsstat3 {
    match error.kind() {
        std::io::ErrorKind::NotFound => nfsstat3::NFS3ERR_NOENT,
        std::io::ErrorKind::PermissionDenied => nfsstat3::NFS3ERR_ACCES,
        std::io::ErrorKind::AlreadyExists => nfsstat3::NFS3ERR_EXIST,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => nfsstat3::NFS3ERR_INVAL,
        std::io::ErrorKind::StorageFull => nfsstat3::NFS3ERR_NOSPC,
        _ => nfsstat3::NFS3ERR_IO,
    }
}

/// Converts host filesystem metadata to legacy NFS attributes.
pub fn metadata_to_fattr3(fid: fileid3, meta: &Metadata) -> fattr3 {
    let size = meta.len();
    let (uid, gid) = metadata_owner(meta);
    let (ftype, nlink) = if meta.is_file() {
        (ftype3::NF3REG, 1)
    } else if meta.file_type().is_symlink() {
        (ftype3::NF3LNK, 1)
    } else {
        (ftype3::NF3DIR, 2)
    };
    fattr3 {
        ftype,
        mode: metadata_mode(meta),
        nlink,
        uid,
        gid,
        size,
        used: size,
        rdev: specdata3::default(),
        fsid: 0,
        fileid: fid,
        atime: metadata_accessed(meta),
        mtime: metadata_modified(meta),
        ctime: metadata_changed(meta),
    }
}

/// Sets attributes on a path using the closest native host semantics.
pub async fn path_setattr(path: &Path, setattr: &sattr3) -> Result<(), nfsstat3> {
    if matches!(setattr.uid, set_uid3::uid(_)) || matches!(setattr.gid, set_gid3::gid(_)) {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }
    match setattr.atime {
        set_atime::SET_TO_SERVER_TIME => {
            filetime::set_file_atime(path, filetime::FileTime::now()).map_err(io_error_to_nfs)?;
        },
        set_atime::SET_TO_CLIENT_TIME(time) => {
            filetime::set_file_atime(path, time.into()).map_err(io_error_to_nfs)?;
        },
        _ => {},
    };
    match setattr.mtime {
        set_mtime::SET_TO_SERVER_TIME => {
            filetime::set_file_mtime(path, filetime::FileTime::now()).map_err(io_error_to_nfs)?;
        },
        set_mtime::SET_TO_CLIENT_TIME(time) => {
            filetime::set_file_mtime(path, time.into()).map_err(io_error_to_nfs)?;
        },
        _ => {},
    };
    if let set_mode3::mode(mode) = setattr.mode {
        debug!(?path, mode, "set permissions");
        set_path_mode(path, mode).map_err(io_error_to_nfs)?;
    }
    if let set_size3::size(size) = setattr.size {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .await
            .map_err(io_error_to_nfs)?;
        debug!(?path, size, "set size");
        file.set_len(size).await.map_err(io_error_to_nfs)?;
    }
    Ok(())
}

/// Sets attributes on an already-open file.
pub async fn file_setattr(file: &std::fs::File, setattr: &sattr3) -> Result<(), nfsstat3> {
    if matches!(setattr.uid, set_uid3::uid(_)) || matches!(setattr.gid, set_gid3::gid(_)) {
        return Err(nfsstat3::NFS3ERR_NOTSUPP);
    }
    if let set_mode3::mode(mode) = setattr.mode {
        debug!(mode, "set permissions");
        set_file_mode(file, mode).map_err(io_error_to_nfs)?;
    }
    if let set_size3::size(size) = setattr.size {
        debug!(size, "set size");
        file.set_len(size).map_err(io_error_to_nfs)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_metadata_updates_return_an_nfs_error() {
        let missing = std::env::temp_dir().join(format!(
            "nfsserve-missing-setattr-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let attributes = sattr3 {
            atime: set_atime::SET_TO_SERVER_TIME,
            ..sattr3::default()
        };
        let error = path_setattr(&missing, &attributes).await.unwrap_err();
        assert_eq!(error as u32, nfsstat3::NFS3ERR_NOENT as u32);
    }
}
