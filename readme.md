# Hells Hollow

Hell's Hollow is a Windows 11 compatible rootkit technique that is equivalent to a modern (PatchGuard and HyperGuard) resistant technique to effectively
perform SSDT Hooking (System Service Dispatch Table) - bypassing all previous defence mechanisms put in the kernel.

This technique works by abusing an undocumented Alternate Syscall handler mechanism in the kernel, within which we are able to climb the stack and 
alter the KTRAP_FRAME, allowing us to effectively hook the SSDT in Windows 11. We are able to decide to either let the OS continue to dispatch the 
system call (and giving us the ability to alter the arguments passed to it), or to alter it on behalf of the dispatcher, and return straight back to 
userland - so the calling application thinks the system call was dispatched normally.

- [Blog post on Hells Hollow](https://fluxsec.red/hells-hollow-a-new-SSDT-hooking-technique-with-alt-syscalls-rootkit)
- [Blog post on Alt Syscalls internals](https://fluxsec.red/alt-syscalls-for-windows-11)

This process looks as follows:

![Hells Hollos SSDT hooking Windows 11](img/full.svg)

I have uploaded this repo as a MVP for producing the technique, it is written in **Rust**, but it works. If you are new to Rust, and simply want to get it up
and running, follow the environment config steps at [Windows Rust Drivers](https://github.com/microsoft/windows-drivers-rs) project and run `cargo make`.

It will spit our a driver that you can simply load with OSR or whatever tool you want. This POC is designed to hook `NtTraceEvent` in the kernel (via Alt Syscalls),
it will modify the return value to 0xff in `rax` to usermode. 

If you want to test this out on a SSN of your choice that isn't `NtTraceEvent`, then make a program called `hello_world.exe` (this rootkit currently filters on that)
and in [alt_syscalls.rs](https://github.com/0xflux/Hells-Hollow/blob/master/src/alt_syscalls.rs) change which SSN you want to hook, which is currently defined as:

```rust
const NT_TRACE_EVENT_SSN: u32 = 0x005e;
```

Then, via either a kernel debugger for the Alt Syscall callback / trap, or a usermode debugger on the syscall itself, you'll see what's going on under the hood.

Video POC coming soon with a bit more of an explanation on what is going on, until then, read my blog :).