#![no_std]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use core::{
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::boxed::Box;
use wdk::{nt_success, println};
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

mod alt_syscalls;
mod thread;
mod utils;

static G_REGISTRY_PATH: AtomicPtr<UNICODE_STRING> = AtomicPtr::new(null_mut());

use wdk_sys::{
    DEVICE_OBJECT, DRIVER_OBJECT, IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, NTSTATUS,
    PCUNICODE_STRING, PDRIVER_OBJECT, PIRP, STATUS_INVALID_BUFFER_SIZE, STATUS_SUCCESS,
    UNICODE_STRING,
    ntddk::{IofCompleteRequest, PsRemoveCreateThreadNotifyRoutine, RtlDuplicateUnicodeString},
};

use crate::{
    alt_syscalls::AltSyscalls,
    thread::{set_thread_creation_callback, thread_callback},
};

#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("Starting Hells Hollow POC by 0xflux, https://github.com/0xflux/.");

    // Initialise the driver, basic stuff, nothing to do with Hell's Hollow here, keep reading for that :~)
    let init = initialise_driver(driver, registry_path);
    if init != STATUS_SUCCESS {
        return init;
    }

    //
    // Now that the driver is initialised we can go ahead and enable Alt Syscalls and thus activate
    // the Hells Hollow technique.
    //
    // First, we need to initialise the structures required to run Alt Syscalls
    // Then, we need to set the appropriate flags per process & thread to enable the Alt Syscall dispatch
    // Finally, the Hells Hollow technique will auto-dispatch in the `syscall_handler` function found in `alt_syscalls.rs`
    //
    AltSyscalls::initialise_for_system(driver);
    set_thread_creation_callback();

    STATUS_SUCCESS
}

fn initialise_driver(driver: &mut DRIVER_OBJECT, registry_path: PCUNICODE_STRING) -> NTSTATUS {
    if registry_path.is_null() {
        println!("Registry path was null, exiting.");
        return STATUS_INVALID_BUFFER_SIZE;
    }

    let mut dup = UNICODE_STRING::default();

    let status = unsafe { RtlDuplicateUnicodeString(1, registry_path, &mut dup) };

    if !nt_success(status) {
        return status;
    }

    let boxed = Box::new(dup);
    G_REGISTRY_PATH.store(Box::into_raw(boxed), Ordering::SeqCst);

    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(drv_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(drv_create_close);
    driver.DriverUnload = Some(driver_exit);

    println!("Hells Hollow registered");

    STATUS_SUCCESS
}

extern "C" fn driver_exit(_driver: PDRIVER_OBJECT) {
    AltSyscalls::uninstall();
    let res = unsafe { PsRemoveCreateThreadNotifyRoutine(Some(thread_callback)) };
    if res != STATUS_SUCCESS {
        println!(
            "Error removing PsSetCreateProcessNotifyRoutineEx from callback routines. Error: {res}"
        );
    }

    let ptr = G_REGISTRY_PATH.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let b = unsafe { Box::from_raw(ptr) };
        drop(b);
    }

    println!("Unloaded Hells Hollow.");
}

unsafe extern "C" fn drv_create_close(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    (unsafe { *pirp }).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (unsafe { *pirp }).IoStatus.Information = 0;
    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };

    STATUS_SUCCESS
}
