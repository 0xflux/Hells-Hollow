use core::{
    ffi::{CStr, c_void},
    slice::from_raw_parts,
};

use alloc::string::String;

use wdk::println;
use wdk_sys::{_EPROCESS, _KTHREAD, LIST_ENTRY, UNICODE_STRING, ntddk::IoThreadToProcess};

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
}

#[derive(Debug)]
/// A custom error enum for the driver
pub enum DriverError {
    NullPtr,
    ModuleNotFound,
    FunctionNotFoundInModule,
    Unknown(String),
}

pub struct ModuleImageBaseInfo {
    pub base_address: *const c_void,
    pub size_of_image: usize,
}

unsafe extern "C" {
    static PsLoadedModuleList: LIST_ENTRY;
}

#[repr(C)]
struct LdrDataTableEntry {
    InLoadOrderLinks: LIST_ENTRY,           // 0x00
    InMemoryOrderLinks: LIST_ENTRY,         // 0x10
    InInitializationOrderLinks: LIST_ENTRY, // 0x20
    DllBase: *const c_void,                 // 0x30
    EntryPoint: *const c_void,              // 0x38
    SizeOfImage: u32,                       // 0x40
    _padding: u32,                          // 0x44
    FullDllName: UNICODE_STRING,            // 0x48
    BaseDllName: UNICODE_STRING,            // 0x58
}

/// Gets the base address and module size of a module in the kernel by traversing the InLoadOrderLinks struct of the `DRIVER_OBJECT`.
///
/// # Returns
/// - `ok` - The function will return `Ok` with a [`ModuleImageBaseInfo`].
/// - `err` - Returns DriverError.
#[inline(always)]
pub fn get_module_base_and_sz(needle: &str) -> Result<ModuleImageBaseInfo, DriverError> {
    let head = unsafe { &PsLoadedModuleList as *const LIST_ENTRY };

    let mut link = unsafe { (*head).Flink };

    while link != head as *mut LIST_ENTRY {
        let entry = link as *mut LdrDataTableEntry;

        let unicode = unsafe { &(*entry).BaseDllName };
        let len = (unicode.Length / 2) as usize;
        let buf = unicode.Buffer;
        if !buf.is_null() && len > 0 && len < 256 {
            let slice = unsafe { from_raw_parts(buf, len) };
            let name = String::from_utf16_lossy(slice);

            if name.eq_ignore_ascii_case(needle) {
                let base = unsafe { (*entry).DllBase };
                let size = unsafe { (*entry).SizeOfImage } as usize;
                return Ok(ModuleImageBaseInfo {
                    base_address: base,
                    size_of_image: size,
                });
            }
        }

        // Move to the next entry
        link = unsafe { (*entry).InLoadOrderLinks.Flink };
    }

    Err(DriverError::ModuleNotFound)
}

/// Scan a loaded module for a particular sequence of bytes, this will most commonly be used to resolve a pointer to
/// an unexported function we wish to use.
///
/// # Args
/// - `image_base`: The base address of the image you wish to search
/// - `image_size`: The total size of the image to search
/// - `pattern`: A byte slice containing the bytes you wish to search for
///
/// # Returns
/// - `ok`: The address of the start of the pattern match
/// - `err`: A [`DriverError`]
pub fn scan_module_for_byte_pattern(
    image_base: *const c_void,
    image_size: usize,
    pattern: &[u8],
) -> Result<*const c_void, DriverError> {
    // Convert the raw address pointer to a byte pointer so we can read individual bytes
    let image_base = image_base as *const u8;
    let mut cursor = image_base as *const u8;
    // End of image denotes the end of our reads, if nothing is found by that point we have not found the
    // sequence of bytes
    let end_of_image = unsafe { image_base.add(image_size) };

    while cursor != end_of_image {
        unsafe {
            let bytes = from_raw_parts(cursor, pattern.len());

            if bytes == pattern {
                return Ok(cursor as *const _);
            }

            cursor = cursor.add(1);
        }
    }

    Err(DriverError::FunctionNotFoundInModule)
}

pub fn thread_to_process_name<'a>(thread: *mut _KTHREAD) -> Result<&'a str, DriverError> {
    let process = unsafe { IoThreadToProcess(thread as *mut _) };

    if process.is_null() {
        println!("PEPROCESS was null.");
        return Err(DriverError::NullPtr);
    }

    eprocess_to_process_name(process as *mut _)
}

pub fn eprocess_to_process_name<'a>(process: *mut _EPROCESS) -> Result<&'a str, DriverError> {
    let name_ptr = unsafe { PsGetProcessImageFileName(process as *mut _) };

    if name_ptr.is_null() {
        println!("Name ptr was null");
    }

    let name = match unsafe { CStr::from_ptr(name_ptr as *const i8) }.to_str() {
        Ok(name_str) => name_str,
        Err(e) => {
            println!("Could not get the process name as a str. {e}");
            return Err(DriverError::ModuleNotFound);
        }
    };

    Ok(name)
}
