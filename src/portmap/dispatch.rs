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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_tcp_nfs_and_mount_v3_mappings_are_advertised() {
        for (prog, vers, prot, expected) in [
            (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, super::IPPROTO_TCP, 20_049),
            (crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, super::IPPROTO_TCP, 20_048),
            (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, crate::portmap::IPPROTO_UDP, 0),
            (crate::nfs3::types::PROGRAM, 2, super::IPPROTO_TCP, 0),
            (crate::mount3::types::PROGRAM, 1, super::IPPROTO_TCP, 0),
            (100_021, 4, super::IPPROTO_TCP, 0),
        ] {
            assert_eq!(
                get_port(
                    &mapping {
                        prog,
                        vers,
                        prot,
                        port: u32::MAX,
                    },
                    20_049,
                    20_048,
                ),
                expected,
            );
        }
    }
}
