use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

use crate::vfs::ExportId;

/// The high cookie bit is reserved by the COMPOUND executor for backend
/// directory cookies when a real directory is overlaid with synthetic
/// namespace children.
pub(crate) const BACKEND_COOKIE_FLAG: u64 = 1 << 63;
const MAX_NAMESPACE_NODES: u64 = BACKEND_COOKIE_FLAG - 2;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct NamespaceNodeId(u64);

impl NamespaceNodeId {
    pub const ROOT: Self = Self(0);

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NamespaceNode {
    id: NamespaceNodeId,
    parent: Option<NamespaceNodeId>,
    name: Vec<u8>,
    children: BTreeMap<Vec<u8>, NamespaceNodeId>,
    export: Option<ExportId>,
}

impl NamespaceNode {
    pub fn id(&self) -> NamespaceNodeId {
        self.id
    }

    #[allow(dead_code)]
    pub fn parent(&self) -> Option<NamespaceNodeId> {
        self.parent
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn export(&self) -> Option<ExportId> {
        self.export
    }

    pub fn children(&self) -> impl ExactSizeIterator<Item = (&[u8], NamespaceNodeId)> {
        self.children.iter().map(|(name, id)| (name.as_slice(), *id))
    }

    pub fn children_after(&self, name: &[u8]) -> impl Iterator<Item = (&[u8], NamespaceNodeId)> {
        self.children
            .range::<[u8], _>((Excluded(name), Unbounded))
            .map(|(name, id)| (name.as_slice(), *id))
    }
}

/// Synthetic, read-only NFSv4 pseudo-filesystem built from export paths.
#[derive(Clone, Debug)]
pub(crate) struct PseudoNamespace {
    nodes: Vec<NamespaceNode>,
    max_nodes: usize,
}

impl PseudoNamespace {
    pub fn new(max_nodes: usize) -> Result<Self, NamespaceError> {
        if max_nodes == 0 || u64::try_from(max_nodes).map_or(true, |limit| limit > MAX_NAMESPACE_NODES) {
            return Err(NamespaceError::InvalidLimit);
        }
        Ok(Self {
            nodes: vec![NamespaceNode {
                id: NamespaceNodeId::ROOT,
                parent: None,
                name: Vec::new(),
                children: BTreeMap::new(),
                export: None,
            }],
            max_nodes,
        })
    }

    pub fn add_export(&mut self, path: &str, export: ExportId) -> Result<NamespaceNodeId, NamespaceError> {
        let components = parse_absolute_path(path)?;
        let mut existing_parent = NamespaceNodeId::ROOT;
        let mut first_missing = components.len();
        for (index, component) in components.iter().enumerate() {
            let Some(child) = self.node(existing_parent)?.children.get(*component).copied() else {
                first_missing = index;
                break;
            };
            existing_parent = child;
        }
        let required_nodes = components.len().saturating_sub(first_missing);
        if self.nodes.len().saturating_add(required_nodes) > self.max_nodes {
            return Err(NamespaceError::Capacity);
        }

        let mut current = NamespaceNodeId::ROOT;
        for component in components {
            let existing = self.node(current)?.children.get(component).copied();
            current = match existing {
                Some(id) => id,
                None => self.add_child(current, component.to_vec())?,
            };
        }
        let node = self.node_mut(current)?;
        if node.export.is_some() {
            return Err(NamespaceError::DuplicateExportPath);
        }
        node.export = Some(export);
        Ok(current)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn root(&self) -> &NamespaceNode {
        &self.nodes[0]
    }

    pub fn node(&self, id: NamespaceNodeId) -> Result<&NamespaceNode, NamespaceError> {
        self.nodes.get(id.0 as usize).ok_or(NamespaceError::UnknownNode)
    }

    pub fn lookup(&self, parent: NamespaceNodeId, name: &[u8]) -> Result<NamespaceNodeId, NamespaceError> {
        validate_component(name)?;
        self.node(parent)?.children.get(name).copied().ok_or(NamespaceError::NotFound)
    }

    /// Resolves a canonical absolute path within the synthetic namespace.
    ///
    /// This deliberately does not cross from an export's namespace node into
    /// its backend. Configuration paths such as the NFSv4 public filehandle
    /// therefore identify pseudo-filesystem nodes, including export roots.
    pub fn resolve_absolute_path(&self, path: &str) -> Result<NamespaceNodeId, NamespaceError> {
        let mut current = NamespaceNodeId::ROOT;
        for component in parse_absolute_path(path)? {
            current = self
                .node(current)?
                .children
                .get(component)
                .copied()
                .ok_or(NamespaceError::NotFound)?;
        }
        Ok(current)
    }

    pub fn lookup_parent(&self, node: NamespaceNodeId) -> Result<NamespaceNodeId, NamespaceError> {
        self.node(node)?.parent.ok_or(NamespaceError::RootParent)
    }

    /// Returns the nearest export mountpoint at or above `node`.
    ///
    /// A non-export node below that mountpoint is an overlay route into the
    /// mounted export's backend. Encountering a nested export deliberately
    /// starts a new route segment.
    pub fn backing_export(&self, node: NamespaceNodeId) -> Result<Option<(ExportId, NamespaceNodeId)>, NamespaceError> {
        let mut current = node;
        loop {
            let current_node = self.node(current)?;
            if let Some(export) = current_node.export {
                return Ok(Some((export, current)));
            }
            let Some(parent) = current_node.parent else {
                return Ok(None);
            };
            current = parent;
        }
    }

    /// Returns the path components strictly below `ancestor` through `node`.
    pub fn relative_components(
        &self,
        ancestor: NamespaceNodeId,
        node: NamespaceNodeId,
    ) -> Result<Vec<&[u8]>, NamespaceError> {
        self.node(ancestor)?;
        let mut components = Vec::new();
        let mut current = node;
        while current != ancestor {
            let current_node = self.node(current)?;
            components.push(current_node.name.as_slice());
            current = current_node.parent.ok_or(NamespaceError::NotDescendant)?;
        }
        components.reverse();
        Ok(components)
    }

    /// Encodes a synthetic child in the cookie range below the backend flag.
    ///
    /// Node IDs are stable for the life of a namespace and make the mapping
    /// allocation-free and reversible.
    pub fn child_cookie(&self, child: NamespaceNodeId) -> Result<u64, NamespaceError> {
        self.node(child)?;
        let cookie = child.0.checked_add(2).ok_or(NamespaceError::CookieOverflow)?;
        if cookie >= BACKEND_COOKIE_FLAG {
            return Err(NamespaceError::CookieOverflow);
        }
        Ok(cookie)
    }

    /// Resolves a synthetic continuation cookie and verifies that it belongs
    /// to `parent`. Cookies from another directory are never accepted.
    pub fn resume_child(&self, parent: NamespaceNodeId, cookie: u64) -> Result<&NamespaceNode, NamespaceError> {
        if !(3..BACKEND_COOKIE_FLAG).contains(&cookie) {
            return Err(NamespaceError::InvalidCookie);
        }
        let child = self
            .node(NamespaceNodeId(cookie - 2))
            .map_err(|_| NamespaceError::InvalidCookie)?;
        if child.parent != Some(parent) {
            return Err(NamespaceError::InvalidCookie);
        }
        Ok(child)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn path(&self, node: NamespaceNodeId) -> Result<Vec<u8>, NamespaceError> {
        let mut components = Vec::new();
        let mut current = node;
        while current != NamespaceNodeId::ROOT {
            let node = self.node(current)?;
            components.push(node.name.as_slice());
            current = node.parent.ok_or(NamespaceError::UnknownNode)?;
        }
        let length = components
            .iter()
            .try_fold(1usize, |length, component| {
                length.checked_add(component.len()).and_then(|length| length.checked_add(1))
            })
            .ok_or(NamespaceError::PathTooLong)?;
        let mut path = Vec::with_capacity(length);
        path.push(b'/');
        for (index, component) in components.into_iter().rev().enumerate() {
            if index != 0 {
                path.push(b'/');
            }
            path.extend_from_slice(component);
        }
        Ok(path)
    }

    fn add_child(&mut self, parent: NamespaceNodeId, name: Vec<u8>) -> Result<NamespaceNodeId, NamespaceError> {
        if self.nodes.len() >= self.max_nodes {
            return Err(NamespaceError::Capacity);
        }
        let id = NamespaceNodeId(self.nodes.len() as u64);
        self.nodes.push(NamespaceNode {
            id,
            parent: Some(parent),
            name: name.clone(),
            children: BTreeMap::new(),
            export: None,
        });
        self.node_mut(parent)?.children.insert(name, id);
        Ok(id)
    }

    fn node_mut(&mut self, id: NamespaceNodeId) -> Result<&mut NamespaceNode, NamespaceError> {
        self.nodes.get_mut(id.0 as usize).ok_or(NamespaceError::UnknownNode)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NamespaceError {
    #[error("pseudo-filesystem node limit is invalid")]
    InvalidLimit,
    #[error("pseudo-filesystem node capacity is exhausted")]
    Capacity,
    #[error("export path must be absolute and canonical")]
    InvalidPath,
    #[error("namespace component is invalid")]
    InvalidComponent,
    #[error("two exports use the same pseudo-filesystem path")]
    DuplicateExportPath,
    #[error("pseudo-filesystem node does not exist")]
    UnknownNode,
    #[error("pseudo-filesystem child does not exist")]
    NotFound,
    #[error("pseudo-filesystem root has no parent")]
    RootParent,
    #[error("pseudo-filesystem path length overflow")]
    #[cfg_attr(not(test), allow(dead_code))]
    PathTooLong,
    #[error("namespace node is not below the requested ancestor")]
    NotDescendant,
    #[error("directory cookie does not identify a child of this node")]
    InvalidCookie,
    #[error("namespace node cannot be represented by a directory cookie")]
    CookieOverflow,
}

fn parse_absolute_path(path: &str) -> Result<Vec<&[u8]>, NamespaceError> {
    if !path.starts_with('/') || (path.len() > 1 && path.ends_with('/')) || path.contains("//") {
        return Err(NamespaceError::InvalidPath);
    }
    if path == "/" {
        return Ok(Vec::new());
    }
    let components: Vec<_> = path.as_bytes()[1..].split(|byte| *byte == b'/').collect();
    for component in &components {
        validate_component(component)?;
    }
    Ok(components)
}

fn validate_component(component: &[u8]) -> Result<(), NamespaceError> {
    if component.is_empty()
        || component == b"."
        || component == b".."
        || component.contains(&0)
        || component.contains(&b'/')
    {
        return Err(NamespaceError::InvalidComponent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_gaps_and_nested_export_overlays() {
        let mut namespace = PseudoNamespace::new(16).unwrap();
        let parent_export = namespace.add_export("/srv", ExportId(1)).unwrap();
        let nested_export = namespace.add_export("/srv/projects/data", ExportId(2)).unwrap();
        let projects = namespace.lookup(parent_export, b"projects").unwrap();
        assert_eq!(namespace.node(projects).unwrap().export(), None);
        assert_eq!(namespace.node(nested_export).unwrap().export(), Some(ExportId(2)));
        assert_eq!(namespace.lookup_parent(nested_export).unwrap(), projects);
        assert_eq!(namespace.path(nested_export).unwrap(), b"/srv/projects/data");
        assert_eq!(namespace.backing_export(projects).unwrap(), Some((ExportId(1), parent_export)));
        assert_eq!(namespace.relative_components(parent_export, projects).unwrap(), vec![b"projects".as_slice()]);
        assert_eq!(namespace.backing_export(nested_export).unwrap(), Some((ExportId(2), nested_export)));
    }

    #[test]
    fn root_export_and_root_parent_are_distinct_rules() {
        let mut namespace = PseudoNamespace::new(4).unwrap();
        assert_eq!(namespace.add_export("/", ExportId(7)).unwrap(), NamespaceNodeId::ROOT);
        assert_eq!(namespace.root().export(), Some(ExportId(7)));
        assert_eq!(namespace.lookup_parent(NamespaceNodeId::ROOT), Err(NamespaceError::RootParent));
    }

    #[test]
    fn rejects_noncanonical_paths_and_duplicate_exports() {
        let mut namespace = PseudoNamespace::new(8).unwrap();
        assert_eq!(namespace.add_export("relative", ExportId(1)), Err(NamespaceError::InvalidPath));
        assert_eq!(namespace.add_export("/a//b", ExportId(1)), Err(NamespaceError::InvalidPath));
        namespace.add_export("/a", ExportId(1)).unwrap();
        assert_eq!(namespace.add_export("/a", ExportId(2)), Err(NamespaceError::DuplicateExportPath));
    }

    #[test]
    fn enforces_namespace_node_capacity_before_mutation() {
        let mut namespace = PseudoNamespace::new(2).unwrap();
        assert_eq!(namespace.add_export("/a/b", ExportId(1)), Err(NamespaceError::Capacity));
        assert_eq!(namespace.lookup(NamespaceNodeId::ROOT, b"a"), Err(NamespaceError::NotFound));
    }

    #[test]
    fn resolves_configured_absolute_namespace_paths() {
        let mut namespace = PseudoNamespace::new(8).unwrap();
        let nested = namespace.add_export("/srv/data", ExportId(1)).unwrap();

        assert_eq!(namespace.resolve_absolute_path("/").unwrap(), NamespaceNodeId::ROOT);
        assert_eq!(namespace.resolve_absolute_path("/srv/data").unwrap(), nested);
        assert_eq!(namespace.resolve_absolute_path("/srv/missing"), Err(NamespaceError::NotFound));
        assert_eq!(namespace.resolve_absolute_path("/srv/../data"), Err(NamespaceError::InvalidComponent));
    }

    #[test]
    fn synthetic_child_cookies_are_stable_reversible_and_directory_scoped() {
        let mut namespace = PseudoNamespace::new(16).unwrap();
        let srv = namespace.add_export("/srv", ExportId(1)).unwrap();
        let data = namespace.add_export("/srv/projects/data", ExportId(2)).unwrap();
        let projects = namespace.lookup(srv, b"projects").unwrap();
        let other = namespace.add_export("/other", ExportId(3)).unwrap();

        let cookie = namespace.child_cookie(data).unwrap();
        assert_eq!(namespace.resume_child(projects, cookie).unwrap().id(), data);
        assert!(matches!(namespace.resume_child(other, cookie), Err(NamespaceError::InvalidCookie)));
        assert!(matches!(namespace.resume_child(projects, 1), Err(NamespaceError::InvalidCookie)));
        assert!(matches!(namespace.resume_child(projects, BACKEND_COOKIE_FLAG), Err(NamespaceError::InvalidCookie)));
    }

    #[test]
    fn relative_components_reject_unrelated_nodes() {
        let mut namespace = PseudoNamespace::new(8).unwrap();
        let left = namespace.add_export("/left", ExportId(1)).unwrap();
        let right = namespace.add_export("/right", ExportId(2)).unwrap();
        assert_eq!(namespace.relative_components(left, right), Err(NamespaceError::NotDescendant));
    }
}
