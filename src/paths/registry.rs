use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use log::{debug, error, warn};

use super::normalized::NormalizedPath;
use super::splice::splice_path;

const TOMBSTONE_FILENAME: &str = ".shim-removed";

pub static PATH_REGISTRY: OnceLock<PathRegistry> = OnceLock::new();

pub struct PathMapping {
    source: NormalizedPath,
    target: NormalizedPath,
}

impl PathMapping {
    pub fn new(source: impl Into<NormalizedPath>, target: impl Into<NormalizedPath>) -> Self {
        PathMapping {
            source: source.into(),
            target: target.into(),
        }
    }
}

/// Registry of virtual path mappings.
pub struct PathRegistry {
    mappings: Vec<PathMapping>,
    masks: Vec<NormalizedPath>,
}

impl PathRegistry {
    pub fn new() -> Self {
        PathRegistry {
            mappings: Vec::new(),
            masks: Vec::new(),
        }
    }

    pub fn register(&mut self, source: impl Into<NormalizedPath>, target: impl Into<NormalizedPath>) {
        let mapping = PathMapping::new(source, target);
        if let Some(shadow) = self.masks.iter().find(|m| mapping.source.starts_with(m)) {
            warn!(
                "[PathRegistry] mapping source {:?} is shadowed by existing mask {:?}, remap will be unreachable",
                mapping.source, shadow
            );
        }
        debug!(
            "[PathRegistry] Registered mapping: {:?} -> {:?}",
            mapping.source, mapping.target
        );
        self.mappings.push(mapping);
    }

    pub fn register_mask(&mut self, source: impl Into<NormalizedPath>) {
        let mask = source.into();
        for shadowed in self.mappings.iter().filter(|m| m.source.starts_with(&mask)) {
            warn!(
                "[PathRegistry] mask {:?} shadows existing mapping source {:?}, remap will be unreachable",
                mask, shadowed.source
            );
        }
        debug!("[PathRegistry] Registered mask: {:?}", mask);
        self.masks.push(mask);
    }

    pub fn register_overlay_dir(&mut self, overlay_root: &Path, exe_dir: &Path) {
        if !overlay_root.is_dir() {
            debug!("[overlay] overlay dir does not exist, skipping: {overlay_root:?}");
            return;
        }

        let entries = match fs::read_dir(overlay_root) {
            Ok(it) => it,
            Err(e) => {
                error!("[overlay] failed to read overlay dir {overlay_root:?}: {e}");
                return;
            }
        };

        let mut wrappers: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        wrappers.sort();

        // First-match-wins: later wrappers can't silently shadow earlier ones.
        let mut claimed: HashSet<NormalizedPath> = HashSet::new();

        for wrapper_pkg in wrappers {
            debug!("[overlay] scanning wrapper package: {wrapper_pkg:?}");
            self.register_overlay_subtree(&wrapper_pkg, &wrapper_pkg, exe_dir, &mut claimed);
        }
    }

    fn register_overlay_subtree(
        &mut self,
        root: &Path,
        current: &Path,
        exe_dir: &Path,
        claimed: &mut HashSet<NormalizedPath>,
    ) {
        // Tombstone applies to the directory it lives in. Mask the dir and
        // skip its contents entirely so a wrapper can't accidentally ship
        // overlay files under a removed path.
        let tombstone = current.join(TOMBSTONE_FILENAME);
        if tombstone.is_file() {
            if current == root {
                error!("[overlay] ignoring tombstone at wrapper root: {tombstone:?}");
            } else if let Ok(rel) = current.strip_prefix(root) {
                self.register_mask(exe_dir.join(rel));
                return;
            }
        }

        let entries = match fs::read_dir(current) {
            Ok(it) => it,
            Err(e) => {
                error!("[overlay] failed to read {current:?}: {e}");
                return;
            }
        };

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                self.register_overlay_subtree(root, &path, exe_dir, claimed);
                continue;
            }
            if path.file_name().is_some_and(|n| n == TOMBSTONE_FILENAME) {
                continue;
            }

            let rel = match path.strip_prefix(root) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            let logical = NormalizedPath::new(exe_dir.join(&rel));
            if !claimed.insert(logical.clone()) {
                error!(
                    "[overlay] collision: {:?} already overlaid by an earlier wrapper, ignoring {:?}",
                    logical, path
                );
                continue;
            }
            self.register(logical, path);
        }
    }

    pub fn try_remap(&self, path: &NormalizedPath) -> Option<PathBuf> {
        for mapping in &self.mappings {
            if let Some(remapped) = splice_path(path, &mapping.source, &mapping.target) {
                return Some(remapped);
            }
        }
        None
    }

    pub fn is_masked(&self, path: &NormalizedPath) -> bool {
        self.masks.iter().any(|m| path.starts_with(m))
    }

    /// Reverse of `try_remap`: maps a target-side path back to its source.
    pub fn reverse_lookup(&self, path: &NormalizedPath) -> Option<PathBuf> {
        for mapping in &self.mappings {
            if let Some(remapped) = splice_path(path, &mapping.target, &mapping.source) {
                return Some(remapped);
            }
        }
        None
    }

    pub fn would_remap(&self, path: &NormalizedPath) -> bool {
        self.try_remap(path).is_some()
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Mods", "D:\\MyMods");
        registry.register("C:\\Game\\Content\\Paks\\LogicMods", "D:\\MyPaks");

        let path = NormalizedPath::new("C:\\Game\\Mods\\test.lua");
        let result = registry.try_remap(&path);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods\\test.lua")));

        let path = NormalizedPath::new("C:\\Game\\Content\\Paks\\LogicMods\\mod.pak");
        let result = registry.try_remap(&path);
        assert_eq!(result, Some(PathBuf::from("D:\\MyPaks\\mod.pak")));
    }

    #[test]
    fn test_registry_no_match() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Mods", "D:\\MyMods");

        let path = NormalizedPath::new("C:\\Other\\file.txt");
        let result = registry.try_remap(&path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_mask_matches_self_and_descendants() {
        let mut registry = PathRegistry::new();
        registry.register_mask("C:\\Game\\Mods\\CheatMod");

        assert!(registry.is_masked(&NormalizedPath::new("C:\\Game\\Mods\\CheatMod")));
        assert!(registry.is_masked(&NormalizedPath::new("C:\\Game\\Mods\\CheatMod\\Scripts\\main.lua")));
        assert!(!registry.is_masked(&NormalizedPath::new("C:\\Game\\Mods\\OtherMod")));
        assert!(!registry.is_masked(&NormalizedPath::new("C:\\Game\\Mods")));
    }

    #[test]
    fn test_mask_independent_of_remap() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Mods", "D:\\MyMods");
        registry.register_mask("C:\\Game\\Mods\\CheatMod");

        // Callers must consult is_masked() first, try_remap is mask-unaware.
        let masked = NormalizedPath::new("C:\\Game\\Mods\\CheatMod\\foo.lua");
        assert!(registry.is_masked(&masked));
        assert!(registry.try_remap(&masked).is_some());

        let unmasked = NormalizedPath::new("C:\\Game\\Mods\\OtherMod\\foo.lua");
        assert!(!registry.is_masked(&unmasked));
        assert_eq!(
            registry.try_remap(&unmasked),
            Some(PathBuf::from("D:\\MyMods\\othermod\\foo.lua"))
        );
    }

    #[test]
    fn test_reverse_lookup_overlay_file_mapping() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Win64\\ue4ss.dll", "D:\\overlay\\Wrap\\ue4ss.dll");

        let target = NormalizedPath::new("D:\\overlay\\Wrap\\ue4ss.dll");
        assert_eq!(
            registry.reverse_lookup(&target),
            Some(PathBuf::from("C:\\Game\\Win64\\ue4ss.dll"))
        );
    }

    #[test]
    fn test_reverse_lookup_through_structural_mapping() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Win64\\Mods", "D:\\MyMods");

        let target = NormalizedPath::new("D:\\MyMods\\SomeMod\\main.lua");
        assert_eq!(
            registry.reverse_lookup(&target),
            Some(PathBuf::from("C:\\Game\\Win64\\Mods\\somemod\\main.lua"))
        );
    }

    #[test]
    fn test_reverse_lookup_no_match() {
        let mut registry = PathRegistry::new();
        registry.register("C:\\Game\\Mods", "D:\\MyMods");

        let unrelated = NormalizedPath::new("E:\\Other\\file.txt");
        assert_eq!(registry.reverse_lookup(&unrelated), None);
    }

    #[test]
    fn test_mask_shadows_overlapping_remap_source() {
        // If a wrapper ships `.shim-removed` inside e.g. `Mods/`, the overlay
        // scan registers a mask at `exe_dir/Mods`, which is also the source
        // of the user's structural mod-dir mapping. Detours consult is_masked
        // before try_remap, so the entire user mod dir becomes unreachable.
        let mut registry = PathRegistry::new();
        registry.register_mask("C:\\Game\\Win64\\Mods");
        registry.register("C:\\Game\\Win64\\Mods", "D:\\UserMods");

        let mod_file = NormalizedPath::new("C:\\Game\\Win64\\Mods\\SomeMod\\main.lua");
        assert!(registry.is_masked(&mod_file));
        assert!(registry.try_remap(&mod_file).is_some());
    }

    #[test]
    fn test_registry_first_match_wins() {
        let mut registry = PathRegistry::new();
        // More specific mapping first
        registry.register("C:\\Game\\Mods\\Special", "D:\\SpecialMods");
        registry.register("C:\\Game\\Mods", "D:\\MyMods");

        // Path under Special should use first mapping
        let path = NormalizedPath::new("C:\\Game\\Mods\\Special\\test.lua");
        let result = registry.try_remap(&path);
        assert_eq!(result, Some(PathBuf::from("D:\\SpecialMods\\test.lua")));

        // Path under Mods (not Special) should use second mapping
        // Note: result path is lowercase due to NormalizedPath normalization
        let path = NormalizedPath::new("C:\\Game\\Mods\\Other\\test.lua");
        let result = registry.try_remap(&path);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods\\other\\test.lua")));
    }
}
