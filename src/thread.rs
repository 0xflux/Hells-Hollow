//! This module handles callback implementations and and other function related to processes.

use core::{arch::asm, ffi::c_void, ptr::null_mut};

use wdk::println;
use wdk_sys::{BOOLEAN, ntddk::PsSetCreateThreadNotifyRoutine};

use crate::{
    alt_syscalls::{AltSyscallStatus, AltSyscalls},
    utils::thread_to_process_name,
};

/// Instructs the driver to register the thread creation callback routine.
pub fn set_thread_creation_callback() {
    if unsafe { PsSetCreateThreadNotifyRoutine(Some(thread_callback)) } != 0 {
        println!("Failed to call set_thread_creation_callback");
    }
}

pub unsafe extern "C" fn thread_callback(
    pid: *mut c_void,
    thread_id: *mut c_void,
    create: BOOLEAN,
) {
    thread_reg_alt_callbacks();
}

pub fn thread_reg_alt_callbacks() {
    let mut ke_thread: *mut c_void = null_mut();

    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) ke_thread,
        )
    };

    let thread_process_name = match thread_to_process_name(ke_thread as *mut _) {
        Ok(t) => t.to_lowercase(),
        Err(e) => {
            println!("Could not get process name on new thread creation. {:?}", e);
            return;
        }
    };

    for needle in ["hello_world"] {
        if thread_process_name.contains(&needle) {
            AltSyscalls::configure_thread_for_alt_syscalls(
                ke_thread as *mut _,
                AltSyscallStatus::Enable,
            );
            AltSyscalls::configure_process_for_alt_syscalls(ke_thread as *mut _);
        }
    }
}
