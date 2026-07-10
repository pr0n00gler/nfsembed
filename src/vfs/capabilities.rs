#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsCapabilities {
    pub read_only: bool,
    pub hard_links: bool,
    pub symbolic_links: bool,
    pub mknod: bool,
    pub homogeneous: bool,
    pub can_set_time: bool,
}

impl VfsCapabilities {
    pub const READ_ONLY: Self = Self {
        read_only: true,
        hard_links: false,
        symbolic_links: false,
        mknod: false,
        homogeneous: true,
        can_set_time: false,
    };

    pub const READ_WRITE: Self = Self {
        read_only: false,
        hard_links: true,
        symbolic_links: true,
        mknod: true,
        homogeneous: true,
        can_set_time: true,
    };
}

impl Default for VfsCapabilities {
    fn default() -> Self {
        Self::READ_ONLY
    }
}
