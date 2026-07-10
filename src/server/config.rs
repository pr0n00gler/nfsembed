#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthPolicy {
    #[default]
    AuthSys,
    Anonymous,
    AuthSysOrAnonymous,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PortmapperMode {
    #[default]
    Disabled,
    Enabled,
}
