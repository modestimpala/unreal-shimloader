use std::ffi::c_void;
use std::ptr::null_mut;

use log::{debug, error, info};
use widestring::U16CString;
use windows_sys::Win32::Foundation::{
    BOOL, HANDLE, INVALID_HANDLE_VALUE, GetLastError, CloseHandle
};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory, RemoveVectoredExceptionHandler
};
use windows_sys::w;

const EXCEPTION_CONTINUE_SEARCH: u32 = 0;
const EXCEPTION_EXECUTE_HANDLER: u32 = 1;

#[repr(C)]
struct MinidumpExceptionInformation {
    thread_id: u32,
    exception_pointers: *const c_void,
    client_pointers: BOOL,
}

type AddVectoredExceptionHandlerFn = unsafe extern "system" fn(
    u32,
    Option<unsafe extern "system" fn(*mut c_void) -> i32>
) -> *mut c_void;

type MiniDumpWriteDumpFn = unsafe extern "system" fn(
    HANDLE, u32, HANDLE, u32,
    *const MinidumpExceptionInformation,
    *const c_void, *const c_void,
) -> BOOL;

// Global variable to store the minidump function pointer
static mut MINI_DUMP_WRITE_DUMP: Option<MiniDumpWriteDumpFn> = None;

// Initialize dbghelp.dll and get the MiniDumpWriteDump function
unsafe fn init_dbghelp() -> bool {
    if let Some(_) = MINI_DUMP_WRITE_DUMP {
        return true;
    }

    let dbghelp = LoadLibraryW(w!("dbghelp.dll"));
    if dbghelp == 0 {
        error!("Failed to load dbghelp.dll");
        return false;
    }

    let proc_addr = GetProcAddress(dbghelp, "MiniDumpWriteDump\0".as_ptr());


    MINI_DUMP_WRITE_DUMP = Some(std::mem::transmute(proc_addr));
    true
}

// Write a minidump to disk
pub unsafe fn write_minidump(exception_ptr: *mut c_void) -> bool {
    if !init_dbghelp() {
        error!("Could not initialize dbghelp.dll");
        return false;
    }

    // Create a unique filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let exe_dir = crate::EXE_DIR.clone();
    let dump_path = exe_dir.join(format!("shimloader_crash_{}.dmp", timestamp));
    
    debug!("Writing minidump to {:?}", dump_path);

    // Convert path to wide string for Windows API
    let wide_path = match U16CString::from_str(dump_path.to_string_lossy().as_ref()) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to convert dump path to wide string: {}", e);
            return false;
        }
    };

    // Create the dump file
    let file_handle = CreateFileW(
        wide_path.as_ptr(),
        0x40000000, // GENERIC_WRITE
        0,          // No sharing
        null_mut(),
        2,          // CREATE_ALWAYS
        0x80,       // FILE_ATTRIBUTE_NORMAL
        0,          // No template
    );

    if file_handle == INVALID_HANDLE_VALUE {
        error!("Failed to create dump file: Error {}", GetLastError());
        return false;
    }

    // Prepare exception info
    let mut exception_param = MinidumpExceptionInformation {
        thread_id: GetCurrentThreadId(),
        exception_pointers: exception_ptr,
        client_pointers: 0,
    };

    // Small-ish minidump flags
    // MiniDumpNormal = 0x00000000
    // MiniDumpWithThreadInfo = 0x00001000
    // MiniDumpWithUnloadedModules = 0x00000020
    // MiniDumpWithIndirectlyReferencedMemory = 0x00000040
    const MINIDUMP_TYPE_SMALLER: u32 = 0x00000000 | 0x00001000 | 0x00000020 | 0x00000040;

    // Write the minidump
    let result = match MINI_DUMP_WRITE_DUMP {
        Some(dump_fn) => dump_fn(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            file_handle,
            MINIDUMP_TYPE_SMALLER, // Use smaller dump type instead of MiniDumpWithFullMemory
            if exception_ptr.is_null() { 
                std::ptr::null() 
            } else { 
                &exception_param as *const _ 
            },
            null_mut(),
            null_mut(),
        ),
        None => 0,
    };

    CloseHandle(file_handle);

    if result == 0 {
        error!("MiniDumpWriteDump failed: Error {}", GetLastError());
        return false;
    }

    info!("Minidump successfully written to: {:?}", dump_path);
    true
}

// The vectored exception handler function
unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut c_void
) -> i32 {
    // Log that we're handling an exception
    error!("Handling exception in vectored exception handler");
    
    // Try to write the minidump
    if write_minidump(exception_info) {
        error!("Minidump created successfully");
    } else {
        error!("Failed to create minidump");
    }

    // Continue searching for other exception handlers
    EXCEPTION_CONTINUE_SEARCH as i32
}

// Function to register the vectored exception handler
pub unsafe fn register_exception_handler() {
    debug!("Registering vectored exception handler");
    
    // Get the kernel32.dll handle
    let kernel32 = LoadLibraryW(w!("kernel32.dll"));
    if kernel32 == 0 {
        error!("Failed to load kernel32.dll");
        return;
    }
    
    // Get the AddVectoredExceptionHandler function
    let add_handler: AddVectoredExceptionHandlerFn = std::mem::transmute(
        GetProcAddress(kernel32, "AddVectoredExceptionHandler\0".as_ptr())
    );
    
    let handler = add_handler(1, Some(vectored_exception_handler));
    
    if handler.is_null() {
        error!("Failed to register vectored exception handler");
    } else {
        debug!("Vectored exception handler registered successfully");
    }
}