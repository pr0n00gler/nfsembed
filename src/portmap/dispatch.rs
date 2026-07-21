use super::{mapping, IPPROTO_TCP};

pub fn get_port(request: &mapping, nfs_port: u16, mount_port: u16) -> u32 {
    if request.prot != IPPROTO_TCP {
        return 0;
    }
    match (request.prog, request.vers) {
        (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION) => u32::from(nfs_port),
        (crate::mount3::types::PROGRAM, crate::mount3::types::VERSION) => u32::from(mount_port),
        _ => 0,
    }
}
