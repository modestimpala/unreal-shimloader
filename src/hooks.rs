use std::collections::HashMap;
use std::sync::Mutex;
use std::{alloc, mem, ptr, slice};
use std::alloc::Layout;
use std::error::Error;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use log::{debug, error};
use once_cell::sync::Lazy;
use retour::static_detour;
use widestring::{U16CStr, U16CString, WideString};
use windows_sys::core::{PCWSTR, PWSTR};
use windows_sys::w;
use windows_sys::Win32::Foundation::{
    GetLastError,
    SetLastError,
    BOOL,
    ERROR_FILE_NOT_FOUND,
    ERROR_NO_MORE_FILES,
    FILETIME,
    HANDLE,
    INVALID_HANDLE_VALUE,
    MAX_PATH,
    NTSTATUS,
    STATUS_OBJECT_NAME_NOT_FOUND,
    UNICODE_STRING,
    HMODULE
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFileHandle, FindFirstFileExW, FindFirstFileW, FindNextFileW, GetFileAttributesExW, GetFileAttributesW, NtCreateFile, FILE_ATTRIBUTE_DIRECTORY, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, FINDEX_INFO_LEVELS, FINDEX_SEARCH_OPS, FIND_FIRST_EX_FLAGS, GET_FILEEX_INFO_LEVELS, NT_CREATE_FILE_DISPOSITION, WIN32_FIND_DATAW
};
use windows_sys::Win32::System::Environment::GetCommandLineW;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, LoadLibraryExW, AddDllDirectory, GetModuleFileNameW, LOAD_LIBRARY_FLAGS};
use windows_sys::Win32::System::WindowsProgramming::{
    IO_STATUS_BLOCK,
    IO_STATUS_BLOCK_0,
    OBJECT_ATTRIBUTES
};
use crate::paths::{self, NormalizedPath, is_masked, remap_path, reverse_remap};

const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;


static_detour! {
    pub static CreateFileW_Detour: unsafe extern "system" fn(
        PCWSTR,
        u32,
        FILE_SHARE_MODE,
        *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION,
        FILE_FLAGS_AND_ATTRIBUTES,
        HANDLE
    ) -> HANDLE;

    pub static NtCreateFile_Detour: unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut OBJECT_ATTRIBUTES,
        *mut IO_STATUS_BLOCK,
        *mut i64,
        u32,
        FILE_SHARE_MODE,
        NT_CREATE_FILE_DISPOSITION,
        u32,
        *mut c_void,
        u32
    ) -> NTSTATUS;

    pub static GetFileAttributesW_Detour: unsafe extern "system" fn(PCWSTR) -> u32;

    pub static GetFileAttributesExW_Detour: unsafe extern "system" fn(
        PCWSTR,
        GET_FILEEX_INFO_LEVELS,
        *mut c_void
    ) -> BOOL;

    pub static FindFirstFileW_Detour: unsafe extern "system" fn(
        PCWSTR,
        *mut WIN32_FIND_DATAW
    ) -> FindFileHandle;

    pub static FindFirstFileExW_Detour: unsafe extern "system" fn(
        PCWSTR,
        FINDEX_INFO_LEVELS,
        *mut c_void,
        FINDEX_SEARCH_OPS,
        *const c_void,
        FIND_FIRST_EX_FLAGS
    ) -> FindFileHandle;

    pub static FindNextFileW_Detour: unsafe extern "system" fn(
        FindFileHandle,
        *mut WIN32_FIND_DATAW
    ) -> BOOL;

    pub static FindClose_Detour: unsafe extern "system" fn(HANDLE) -> BOOL;

    pub static LoadLibraryW_Detour: unsafe extern "system" fn(PCWSTR) -> HMODULE;

    pub static LoadLibraryExW_Detour: unsafe extern "system" fn(PCWSTR, HANDLE, LOAD_LIBRARY_FLAGS) -> HMODULE;

    pub static AddDllDirectory_Detour: unsafe extern "system" fn(PCWSTR) -> *mut c_void;

    pub static GetCommandLineW_Detour: unsafe extern "system" fn() -> PCWSTR;

    pub static GetModuleFileNameW_Detour: unsafe extern "system" fn(HMODULE, PWSTR, u32) -> u32;
}

/// Switches that the shimloader consumes itself. They (and their following value)
/// must be stripped from the command line before the game's own parser sees them,
/// otherwise UE5's `FCommandLine`/`UGameInstance::StartGameInstance` interprets the
/// path that follows as a map URL and pops a "map could not be found" dialog.
const SHIMLOADER_SWITCHES: &[&str] = &["--mod-dir", "--pak-dir", "--cfg-dir", "--overlay-dir"];

/// Cached, sanitized copy of the process command line. The pointer returned by
/// `getcommandlinew_detour` must remain valid for the entire lifetime of the
/// process, so we hold the backing storage in a `OnceCell`.
static SANITIZED_COMMAND_LINE: Lazy<U16CString> = Lazy::new(|| unsafe {
    let original_ptr = GetCommandLineW_Detour.call();
    let original = U16CStr::from_ptr_str(original_ptr).as_slice();
    let cleaned = sanitize_command_line(original);
    U16CString::from_vec_truncate(cleaned)
});


pub unsafe fn enable_hooks() -> Result<(), Box<dyn Error>> {
    CreateFileW_Detour.initialize(CreateFileW, |a, b, c, d, e, f, g| unsafe {
        createfilew_detour(
            a,
            b,
            c,
            d,
            e,
            f,
            g
        )
    })?;

    NtCreateFile_Detour.initialize(NtCreateFile, |a, b, c, d, e, f, g, h, i, j, k| {
        ntcreatefile_detour(
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
            i,
            j,
            k,
        )
    })?.enable()?;

    GetFileAttributesW_Detour.initialize(GetFileAttributesW, |a| unsafe {
        getfileattributesw_detour(a)
    })?.enable()?;

    GetFileAttributesExW_Detour.initialize(GetFileAttributesExW, |a, b, c| unsafe {
        getfileattributesexw_detour(a, b, c)
    })?.enable()?;

    FindFirstFileW_Detour.initialize(FindFirstFileW, |a, b| unsafe {
        findfirstfilew_detour(a, b)
    })?.enable()?;

    FindFirstFileExW_Detour.initialize(FindFirstFileExW, |a, b, c, d, e, f| unsafe {
        findfirstfileexw_detour(a, b, c, d, e, f)
    })?.enable()?;

    FindNextFileW_Detour.initialize(FindNextFileW, |a, b| unsafe {
        findnextfilew_detour(a, b)
    })?.enable()?;

    FindClose_Detour.initialize(FindClose, |a| unsafe {
        findclose_detour(a)
    })?.enable()?;

    LoadLibraryW_Detour.initialize(LoadLibraryW, |lpfilename| unsafe {
        loadlibraryw_detour(lpfilename)
    })?.enable()?;

    LoadLibraryExW_Detour.initialize(LoadLibraryExW, |lpfilename, hfile, dwflags| unsafe {
        loadlibraryexw_detour(lpfilename, hfile, dwflags)
    })?.enable()?;

    AddDllDirectory_Detour.initialize(AddDllDirectory, |lppathnamestr| unsafe {
        adddlldirectory_detour(lppathnamestr)
    })?.enable()?;

    GetCommandLineW_Detour.initialize(GetCommandLineW, || unsafe {
        getcommandlinew_detour()
    })?.enable()?;

    GetModuleFileNameW_Detour.initialize(GetModuleFileNameW, |h, b, s| unsafe {
        getmodulefilenamew_detour(h, b, s)
    })?.enable()?;


    Ok(())
}

pub unsafe extern "system" fn createfilew_detour(
    raw_file_name: PCWSTR,
    desired_access: u32,
    share_mode: FILE_SHARE_MODE,
    security_attributes: *const SECURITY_ATTRIBUTES,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    template_file: HANDLE,
) -> HANDLE {
    let path = paths::pcwstr_to_path(raw_file_name);
    if is_masked(&path) {
        debug!("[createfilew_detour] masked: {:?}", path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[createfilew_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = wide_path.as_ptr();

    CreateFileW_Detour.call(
        raw_path,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_attributes,
        template_file
    )
}

pub unsafe extern "system" fn ntcreatefile_detour(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attrs: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *mut i64,
    file_attrs: u32,
    share_access: FILE_SHARE_MODE,
    creation_disposition: NT_CREATE_FILE_DISPOSITION,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NTSTATUS {
    // The path is stored a couple layers deep in a UNICODE_STRING struct. Lets grab it.
    let unicode_path = *(*object_attrs).ObjectName;
    let path_len = (unicode_path.Length / 2) as usize;

    // Strip the Rtl prefix from the given string. We need to reintroduce this later.
    let og_prefix = slice::from_raw_parts(unicode_path.Buffer, 4);
    let offset_path = unicode_path.Buffer.add(4);

    // Create a raw slice and handle potential nulls safely
    let slice = slice::from_raw_parts(offset_path, path_len - 4);

    // Find the first null terminator, if any
    let null_pos = slice.iter().position(|&c| c == 0);

    let effective_len = null_pos.unwrap_or(path_len - 4);
    let effective_slice = &slice[..effective_len];

    // Use from_vec instead of from_slice
    let wide_string = WideString::from_vec(effective_slice.to_vec());
    let original_path_result = wide_string.to_string();

    // Early return if we can't process the path
    if original_path_result.is_err() {
        return NtCreateFile_Detour.call(
            file_handle,
            desired_access,
            object_attrs,
            io_status_block,
            allocation_size,
            file_attrs,
            share_access,
            creation_disposition,
            create_options,
            ea_buffer,
            ea_length
        );
    }

    let original_path_str = original_path_result.unwrap();

    let bad_path_prefixes = ["\\\\device", "c:\\windows"];
    if bad_path_prefixes.iter().any(|x| {
        let lowercase = original_path_str.to_lowercase();
        lowercase.starts_with(&x.to_lowercase())
    }) {
        return NtCreateFile_Detour.call(
            file_handle,
            desired_access,
            object_attrs,
            io_status_block,
            allocation_size,
            file_attrs,
            share_access,
            creation_disposition,
            create_options,
            ea_buffer,
            ea_length
        );
    };

    let original_path = PathBuf::from(original_path_str);
    let new_path = NormalizedPath::new(&original_path);
    if is_masked(&new_path) {
        debug!("[ntcreatefile_detour] masked: {:?}", original_path);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let new_path = remap_path(&new_path).unwrap_or_else(|| new_path.to_path_buf());

    debug!("[ntcreatefile_detour] {:?} to {:?}", original_path, new_path);

    // Update the Length property in the UNICODE_STRING struct with the new length of the path.
    // (+ convert the new path back into a raw widestring and copy it into the buffer.)
    let wide_new_path = paths::path_to_widestring(&new_path);
    let new_path_size = (wide_new_path.len() * 2) + 8;

    let buffer_layout = Layout::array::<u16>(og_prefix.len() + wide_new_path.len() + 1).unwrap();
    let buffer = alloc::alloc_zeroed(buffer_layout).cast::<u16>();

    // The length of the buffer in bytes.
    let used_size = (og_prefix.len() + wide_new_path.len()) * 2;
    let buffer_size = used_size + 2;

    ptr::copy_nonoverlapping(og_prefix.as_ptr(), buffer, og_prefix.len());
    ptr::copy_nonoverlapping(wide_new_path.as_ptr(), buffer.add(og_prefix.len()), wide_new_path.len());

    let mut new_unicode = UNICODE_STRING {
        Length: used_size as _,
        MaximumLength: buffer_size as _,
        Buffer: buffer,
    };

    (*object_attrs).ObjectName = ptr::addr_of_mut!(new_unicode);

    // Call NtCreateFile now, we need to do some forgettin' before we can be done.
    NtCreateFile_Detour.call(
        file_handle,
        desired_access,
        object_attrs,
        io_status_block,
        allocation_size,
        file_attrs,
        share_access,
        creation_disposition,
        create_options,
        ea_buffer,
        ea_length
    )
}

unsafe extern "system" fn getfileattributesw_detour(
    raw_file_name: PCWSTR,
) -> u32 {
    let path = paths::pcwstr_to_path(raw_file_name);
    if is_masked(&path) {
        debug!("[getfileattributesw_detour] masked: {:?}", path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[getfileattributesw_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = if path.to_path_buf() == new_path {
        raw_file_name
    } else {
        wide_path.as_ptr()
    };

    GetFileAttributesW_Detour.call(
        raw_path
    )
}

unsafe extern "system" fn getfileattributesexw_detour(
    raw_file_name: PCWSTR,
    info_level_id: GET_FILEEX_INFO_LEVELS,
    file_information: *mut c_void,
) -> BOOL {
    let path = paths::pcwstr_to_path(raw_file_name);
    if is_masked(&path) {
        debug!("[getfileattributesexw_detour] masked: {:?}", path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[getfileattributesexw_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    // Use the original Windows API to get attributes
    let attrs = GetFileAttributesW(wide_path.as_ptr());

    // If the path doesn't exist, handle it properly
    if attrs == 0xFFFFFFFF {
        // The error is already set by GetFileAttributesW
        return 0;
    }

    // Call the original function with our path
    GetFileAttributesExW_Detour.call(
        wide_path.as_ptr(),
        info_level_id,
        file_information
    )
}

// Per-handle: pre-remap search dir, used by FindNextFileW to filter masked entries.
static SEARCH_HANDLES: Lazy<Mutex<HashMap<isize, NormalizedPath>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

unsafe fn read_find_data_filename(find_data: *const WIN32_FIND_DATAW) -> String {
    if find_data.is_null() {
        return String::new();
    }
    let buf = (*find_data).cFileName;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn search_dir_for_pattern(pattern: &NormalizedPath) -> Option<NormalizedPath> {
    pattern.original().parent().map(NormalizedPath::new)
}

unsafe fn advance_past_masked(
    handle: HANDLE,
    find_file_data: *mut WIN32_FIND_DATAW,
    search_dir: &NormalizedPath,
) -> bool {
    loop {
        let name = read_find_data_filename(find_file_data);
        if name.is_empty() || name == "." || name == ".." {
            return true;
        }
        let candidate = search_dir.join(&name);
        if !is_masked(&candidate) {
            return true;
        }
        debug!("[find filter] masked entry skipped: {:?}", candidate);
        if FindNextFileW_Detour.call(handle, find_file_data) == 0 {
            return false;
        }
    }
}

unsafe extern "system" fn findfirstfilew_detour(
    raw_file_name: PCWSTR,
    find_file_data: *mut WIN32_FIND_DATAW,
) -> FindFileHandle {
    let path = paths::pcwstr_to_path(raw_file_name);
    if is_masked(&path) {
        debug!("[findfirstfilew_detour] masked: {:?}", path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[findfirstfilew_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = if path.to_path_buf() == new_path {
        raw_file_name
    } else {
        wide_path.as_ptr()
    };

    let handle = FindFirstFileW_Detour.call(raw_path, find_file_data);
    if handle == INVALID_HANDLE_VALUE {
        return handle;
    }

    if let Some(search_dir) = search_dir_for_pattern(&path) {
        if !advance_past_masked(handle, find_file_data, &search_dir) {
            FindClose_Detour.call(handle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
        SEARCH_HANDLES
            .lock()
            .unwrap()
            .insert(handle, search_dir);
    }

    handle
}

unsafe extern "system" fn findfirstfileexw_detour(
    raw_file_name: PCWSTR,
    info_level_id: FINDEX_INFO_LEVELS,
    find_file_data: *mut c_void,
    search_op: FINDEX_SEARCH_OPS,
    search_filter: *const c_void,
    additional_flags: FIND_FIRST_EX_FLAGS
) -> FindFileHandle {
    let path = paths::pcwstr_to_path(raw_file_name);
    if is_masked(&path) {
        debug!("[findfirstfileexw_detour] masked: {:?}", path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[findfirstfileexw_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = wide_path.as_ptr();

    let handle = FindFirstFileExW_Detour.call(
        raw_path,
        info_level_id,
        find_file_data,
        search_op,
        search_filter,
        additional_flags
    );
    if handle == INVALID_HANDLE_VALUE {
        return handle;
    }

    if let Some(search_dir) = search_dir_for_pattern(&path) {
        let win32_data = find_file_data.cast::<WIN32_FIND_DATAW>();
        if !advance_past_masked(handle, win32_data, &search_dir) {
            FindClose_Detour.call(handle);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
        SEARCH_HANDLES
            .lock()
            .unwrap()
            .insert(handle, search_dir);
    }

    handle
}

unsafe extern "system" fn findnextfilew_detour(
    handle: FindFileHandle,
    find_file_data: *mut WIN32_FIND_DATAW,
) -> BOOL {
    let result = FindNextFileW_Detour.call(handle, find_file_data);
    if result == 0 {
        return result;
    }

    let search_dir = SEARCH_HANDLES.lock().unwrap().get(&handle).cloned();
    if let Some(search_dir) = search_dir {
        if !advance_past_masked(handle, find_file_data, &search_dir) {
            SetLastError(ERROR_NO_MORE_FILES);
            return 0;
        }
    }

    1
}

unsafe extern "system" fn findclose_detour(handle: HANDLE) -> BOOL {
    SEARCH_HANDLES.lock().unwrap().remove(&handle);
    FindClose_Detour.call(handle)
}


unsafe extern "system" fn loadlibraryw_detour(lpfilename: PCWSTR) -> HMODULE {
    let path = paths::pcwstr_to_path(lpfilename);
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());
    debug!("[loadlibraryw_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = wide_path.as_ptr();

    LoadLibraryW_Detour.call(raw_path)
}

/// Required for experimental UE4SS debug builds. As of ed989df they use LoadLibraryExW to load their DLLs instead of LoadLibraryW
unsafe extern "system" fn loadlibraryexw_detour(lpfilename: PCWSTR, hfile: HANDLE, dwflags: LOAD_LIBRARY_FLAGS) -> HMODULE {
    let path = paths::pcwstr_to_path(lpfilename);
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());
    debug!("[loadlibraryexw_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);

    let raw_path = wide_path.as_ptr();

    LoadLibraryExW_Detour.call(raw_path, hfile, dwflags)
}

unsafe extern "system" fn adddlldirectory_detour(lppathnamestr: PCWSTR) -> *mut c_void {
    let path = paths::pcwstr_to_path(lppathnamestr);
    let new_path = remap_path(&path).unwrap_or_else(|| path.to_path_buf());

    debug!("[adddlldirectory_detour] {:?} to {:?}", path, new_path);

    let wide_path = paths::path_to_widestring(&new_path);
    let raw_path = wide_path.as_ptr();

    AddDllDirectory_Detour.call(raw_path)
}

unsafe extern "system" fn getcommandlinew_detour() -> PCWSTR {
    SANITIZED_COMMAND_LINE.as_ptr()
}

/// Spoof `GetModuleFileNameW` results for overlay-loaded modules so callers
/// see the logical Win64 path. Without this, UE4SS derives its mods/settings/log
/// dirs from the wrapper location and bypasses Win64-relative detours.
unsafe extern "system" fn getmodulefilenamew_detour(
    h_module: HMODULE,
    lp_filename: PWSTR,
    n_size: u32,
) -> u32 {
    let result = GetModuleFileNameW_Detour.call(h_module, lp_filename, n_size);
    if result == 0 || n_size == 0 {
        return result;
    }

    let written = result as usize;
    let buf_slice = slice::from_raw_parts(lp_filename, written);
    let actual_str = match WideString::from_vec(buf_slice.to_vec()).to_string() {
        Ok(s) => s,
        Err(_) => return result,
    };

    let actual_path = NormalizedPath::new(&actual_str);
    let Some(source_path) = reverse_remap(&actual_path) else {
        return result;
    };

    let source_str = source_path.to_string_lossy();
    let Ok(source_wide) = U16CString::from_str(source_str.as_ref()) else {
        return result;
    };

    let with_nul = source_wide.as_slice_with_nul();
    if with_nul.len() as u32 <= n_size {
        ptr::copy_nonoverlapping(with_nul.as_ptr(), lp_filename, with_nul.len());
        (with_nul.len() - 1) as u32
    } else {
        // Win XP+ behavior on overflow: truncate, no null terminator, return n_size.
        ptr::copy_nonoverlapping(with_nul.as_ptr(), lp_filename, n_size as usize);
        SetLastError(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER);
        n_size
    }
}

/// Tokenize a Windows command line and emit a copy with the shimloader's own
/// switches (and the value following each one) removed. Whitespace and quoting
/// inside the surviving tokens is preserved verbatim.
fn sanitize_command_line(input: &[u16]) -> Vec<u16> {
    let tokens = tokenize_command_line(input);

    let mut keep = vec![true; tokens.len()];
    let mut skip_next = false;
    for (i, tok) in tokens.iter().enumerate() {
        if skip_next {
            keep[i] = false;
            skip_next = false;
            continue;
        }

        let unquoted = unquote_token(&input[tok.start..tok.end]);
        if SHIMLOADER_SWITCHES.iter().any(|s| unquoted.eq_ignore_ascii_case(s)) {
            keep[i] = false;
            skip_next = true;
        }
    }

    let mut out: Vec<u16> = Vec::with_capacity(input.len());
    let mut first_kept = true;
    for (i, tok) in tokens.iter().enumerate() {
        if !keep[i] {
            continue;
        }

        if first_kept {
            // Preserve the original leading whitespace and argv[0] verbatim.
            out.extend_from_slice(&input[..tok.end]);
            first_kept = false;
        } else {
            out.push(b' ' as u16);
            out.extend_from_slice(&input[tok.start..tok.end]);
        }
    }

    out
}

struct CmdToken {
    start: usize,
    end: usize,
}

/// Split a wide command line into token byte ranges, honouring double-quote
/// grouping so that paths containing spaces are kept intact.
fn tokenize_command_line(input: &[u16]) -> Vec<CmdToken> {
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const QUOTE: u16 = b'"' as u16;

    let mut tokens = Vec::new();
    let mut i = 0;
    while i < input.len() {
        // Skip whitespace between tokens.
        while i < input.len() && (input[i] == SPACE || input[i] == TAB) {
            i += 1;
        }
        if i >= input.len() {
            break;
        }

        let start = i;
        let mut in_quote = false;
        while i < input.len() {
            let c = input[i];
            if c == QUOTE {
                in_quote = !in_quote;
            } else if !in_quote && (c == SPACE || c == TAB) {
                break;
            }
            i += 1;
        }
        tokens.push(CmdToken { start, end: i });
    }
    tokens
}

/// Strip a single layer of surrounding double quotes from a wide token and
/// decode the result for switch comparison. Non-UTF16 sequences are skipped.
fn unquote_token(token: &[u16]) -> String {
    const QUOTE: u16 = b'"' as u16;
    let trimmed = if token.len() >= 2 && token[0] == QUOTE && token[token.len() - 1] == QUOTE {
        &token[1..token.len() - 1]
    } else {
        token
    };
    String::from_utf16_lossy(trimmed)
}
