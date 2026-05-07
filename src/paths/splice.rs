use std::path::PathBuf;

use super::normalized::NormalizedPath;
use super::registry::PATH_REGISTRY;

/// Re-map a path through the global path registry.
pub fn remap_path(path: &NormalizedPath) -> Option<PathBuf> {
    PATH_REGISTRY.get().and_then(|registry| registry.try_remap(path))
}

pub fn is_masked(path: &NormalizedPath) -> bool {
    PATH_REGISTRY.get().is_some_and(|registry| registry.is_masked(path))
}

/// Reverse-map a path through the global path registry.
pub fn reverse_remap(path: &NormalizedPath) -> Option<PathBuf> {
    PATH_REGISTRY.get().and_then(|registry| registry.reverse_lookup(path))
}

/// Splice a path from one root onto another.
/// Returns the remapped path if `path` starts with `source_root`, otherwise None.
pub fn splice_path(
    path: &NormalizedPath,
    source_root: &NormalizedPath,
    target_root: &NormalizedPath,
) -> Option<PathBuf> {
    if !path.starts_with(source_root) {
        return None;
    }

    let relative = path.strip_prefix(source_root)?;
    // Avoid Path::join(""): Win32 CreateFile rejects file paths ending in `\`.
    let result = if relative.as_os_str().is_empty() {
        target_root.to_path_buf()
    } else {
        target_root.to_path_buf().join(relative)
    };

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splice_path_basic() {
        let path = NormalizedPath::new("C:\\Game\\Mods\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods\\test.lua")));
    }

    #[test]
    fn test_splice_path_nested() {
        let path = NormalizedPath::new("C:\\Game\\Mods\\subdir\\another\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods\\subdir\\another\\test.lua")));
    }

    #[test]
    fn test_splice_path_not_under_source() {
        let path = NormalizedPath::new("C:\\Other\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, None);
    }

    #[test]
    fn test_splice_path_parent_does_not_match() {
        // This is the critical bug fix test!
        // A path that is a PARENT of source should NOT match.
        let path = NormalizedPath::new("C:\\Game");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, None);
    }

    #[test]
    fn test_splice_path_exact_match() {
        // The exact directory itself should match, returning just the target.
        let path = NormalizedPath::new("C:\\Game\\Mods");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods")));
    }

    #[test]
    fn test_splice_path_exact_match_no_trailing_separator() {
        // PathBuf component-equality hides trailing `\`, check raw bytes.
        let path = NormalizedPath::new("C:\\Game\\Win64\\UE4SS-settings.ini");
        let source = NormalizedPath::new("C:\\Game\\Win64\\UE4SS-settings.ini");
        let target = NormalizedPath::new("D:\\overlay\\Wrap\\UE4SS-settings.ini");

        let result = splice_path(&path, &source, &target).unwrap();
        let bytes = result.as_os_str().to_string_lossy();
        assert!(!bytes.ends_with('\\'), "remap target must not end with backslash, got {bytes:?}");
        assert_eq!(bytes, "D:\\overlay\\Wrap\\UE4SS-settings.ini");
    }

    #[test]
    fn test_splice_path_case_insensitive() {
        let path = NormalizedPath::new("C:\\GAME\\MODS\\test.lua");
        let source = NormalizedPath::new("c:\\game\\mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, Some(PathBuf::from("D:\\MyMods\\test.lua")));
    }

    // Edge case: UNC paths should NOT match local paths
    #[test]
    fn test_unc_path_not_remapped() {
        let path = NormalizedPath::new("\\\\server\\share\\Mods\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, None);
    }

    // Edge case: Different drives should NOT match
    #[test]
    fn test_different_drive_not_remapped() {
        let path = NormalizedPath::new("E:\\Game\\Mods\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, None);
    }

    // Edge case: Similar prefix but different directory
    #[test]
    fn test_similar_prefix_not_remapped() {
        let path = NormalizedPath::new("C:\\Game\\ModsBackup\\test.lua");
        let source = NormalizedPath::new("C:\\Game\\Mods");
        let target = NormalizedPath::new("D:\\MyMods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, None);
    }

    // Test case matching the real-world DLL loading scenario
    #[test]
    fn test_dll_path_remapping() {
        let path = NormalizedPath::new(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64\Mods\AutoIntegrator\dlls\main.dll");
        let source = NormalizedPath::new(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64\Mods");
        let target = NormalizedPath::new(r"C:\Users\Test\Mods");

        let result = splice_path(&path, &source, &target);
        assert_eq!(result, Some(PathBuf::from(r"C:\Users\Test\Mods\autointegrator\dlls\main.dll")));
    }

    // Test case: source path built with .join() like in lib.rs
    #[test]
    fn test_exe_dir_join_mods() {
        // Simulating EXE_DIR.join("Mods") where EXE_DIR comes from env::current_exe().parent()
        let exe_dir = PathBuf::from(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64");
        let source = NormalizedPath::new(exe_dir.join("Mods"));

        let path = NormalizedPath::new(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64\Mods\AutoIntegrator\dlls\main.dll");
        let target = NormalizedPath::new(r"C:\Users\Test\MyMods");

        println!("Source inner: {:?}", source.inner());
        println!("Path inner: {:?}", path.inner());
        println!("Path starts_with source: {}", path.starts_with(&source));

        let result = splice_path(&path, &source, &target);
        assert!(result.is_some(), "Path should be remapped");
        println!("Result: {:?}", result);
    }

    // Test case: extended-length path prefix (\\?\)
    #[test]
    fn test_extended_length_path() {
        let path = NormalizedPath::new(r"\\?\D:\Games\Mods\test.dll");
        let source = NormalizedPath::new(r"D:\Games\Mods");
        let target = NormalizedPath::new(r"C:\MyMods");

        println!("Path inner: {:?}", path.inner());
        println!("Source inner: {:?}", source.inner());
        println!("Path starts_with source: {}", path.starts_with(&source));

        let result = splice_path(&path, &source, &target);
        // Extended-length paths have different prefix component - they won't match!
        println!("Result: {:?}", result);
    }

    // Test what happens if source is registered with trailing backslash
    #[test]
    fn test_trailing_separator_mismatch() {
        let path = NormalizedPath::new(r"D:\Games\Mods\test.dll");
        let source_with_slash = NormalizedPath::new(r"D:\Games\Mods\");
        let source_without = NormalizedPath::new(r"D:\Games\Mods");
        let target = NormalizedPath::new(r"C:\MyMods");

        println!("Path inner: {:?}", path.inner());
        println!("Source with trailing: {:?}", source_with_slash.inner());
        println!("Source without trailing: {:?}", source_without.inner());

        let result1 = splice_path(&path, &source_with_slash, &target);
        let result2 = splice_path(&path, &source_without, &target);

        println!("Result with trailing slash source: {:?}", result1);
        println!("Result without trailing slash source: {:?}", result2);
    }

    // Test exact lib.rs scenario
    #[test]
    fn test_lib_rs_registration_scenario() {
        use std::path::PathBuf;

        // Simulate EXE_DIR from env::current_exe().parent()
        let exe_dir = PathBuf::from(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64");

        // This is how lib.rs registers: registry.register(EXE_DIR.join("Mods"), ...)
        let source = NormalizedPath::new(exe_dir.join("Mods"));
        let target = NormalizedPath::new(r"C:\Users\Test\MyMods");

        println!("Source (from join): {:?}", source.inner());

        // This is the path UE4SS would try to access
        let dll_path = NormalizedPath::new(r"D:\Games\steamapps\common\ASTRONEER\Astro\Binaries\Win64\Mods\AutoIntegrator\dlls\main.dll");

        println!("DLL path: {:?}", dll_path.inner());
        println!("starts_with: {}", dll_path.starts_with(&source));

        let result = splice_path(&dll_path, &source, &target);
        assert!(result.is_some(), "DLL path should be remapped! Got: {:?}", result);
        println!("Remapped: {:?}", result);
    }
}
