#![no_std]
#![no_main]

mod arch;
mod boot_alloc;
mod memory;
mod serial;
mod uefi;

use core::arch::asm;
use core::panic::PanicInfo;

use arch::x86_64::{descriptors, paging::HostPageTables, vm, vmx};
use boot_alloc::BootArena;
use memory::{FrameAllocator, MemoryMap};
use serial::{log_hex, log_line};
use uefi::{EfiHandle, EfiStatus, EfiSystemTable, Handoff, Loader};

#[unsafe(no_mangle)]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> EfiStatus {
    serial::init();
    log_line("hypewwisoww: UEFI entry");

    let mut loader = match unsafe { Loader::new(image_handle, system_table) } {
        Ok(loader) => loader,
        Err(status) => return status,
    };

    let prepared = match loader.prepare() {
        Ok(prepared) => prepared,
        Err(status) => {
            log_hex("hypewwisoww: preparation failed, EFI_STATUS=", status as u64);
            return status;
        }
    };

    log_line("hypewwisoww: leaving UEFI boot services");
    let handoff = match loader.exit_boot_services(prepared) {
        Ok(handoff) => handoff,
        Err(status) => {
            log_hex("hypewwisoww: ExitBootServices failed, EFI_STATUS=", status as u64);
            return status;
        }
    };

    unsafe { asm!("cli", options(nomem, nostack)) };
    unsafe { enter_core((*handoff).stack_top, handoff) }
}

unsafe fn enter_core(stack_top: u64, handoff: *const Handoff) -> ! {
    unsafe {
        asm!(
            "mov rsp, {stack}",
            "and rsp, -16",
            "mov rdi, {handoff}",
            "call {entry}",
            "ud2",
            stack = in(reg) stack_top,
            handoff = in(reg) handoff,
            entry = sym hypervisor_main,
            options(noreturn)
        )
    }
}

extern "sysv64" fn hypervisor_main(handoff: *const Handoff) -> ! {
    log_line("hypewwisoww: boot services exited; core owns execution");

    if handoff.is_null() {
        fatal("null UEFI handoff");
    }

    let handoff = unsafe { &*handoff };
    log_hex("hypewwisoww: memory-map bytes=", handoff.memory_map_size as u64);
    log_hex("hypewwisoww: descriptor bytes=", handoff.descriptor_size as u64);

    let mut arena = match unsafe {
        BootArena::new(handoff.bootstrap_arena_base, handoff.bootstrap_arena_size)
    } {
        Ok(arena) => arena,
        Err(error) => {
            log_hex("hypewwisoww: invalid bootstrap arena=", error as u64);
            halt_forever();
        }
    };

    let descriptor_state =
        match unsafe { descriptors::install(&mut arena, handoff.stack_top) } {
            Ok(state) => state,
            Err(error) => {
                log_hex("hypewwisoww: descriptor setup failed=", error as u64);
                halt_forever();
            }
        };
    log_line("hypewwisoww: host GDT/TSS/IDT active");
    log_hex("hypewwisoww: bootstrap arena remaining=", arena.remaining_bytes());

    let map = match unsafe { MemoryMap::from_handoff(handoff) } {
        Ok(map) => map,
        Err(error) => {
            log_hex("hypewwisoww: invalid memory map=", error as u64);
            halt_forever();
        }
    };
    log_hex("hypewwisoww: memory descriptors=", map.descriptor_count() as u64);
    let frames = match FrameAllocator::from_memory_map(map) {
        Ok(frames) => frames,
        Err(error) => {
            log_hex("hypewwisoww: frame ledger failed=", error as u64);
            halt_forever();
        }
    };
    log_hex("hypewwisoww: free ranges=", frames.range_count() as u64);
    log_hex("hypewwisoww: free 4K frames=", frames.total_pages());

    let vm_resources = match vm::VmResources::allocate(&mut arena) {
        Ok(resources) => resources,
        Err(error) => {
            log_hex("hypewwisoww: VM resource allocation failed=", error as u64);
            halt_forever();
        }
    };

    let guard_pages = [
        handoff.stack_guard,
        descriptor_state.ist_guard_pages[0],
        descriptor_state.ist_guard_pages[1],
        descriptor_state.ist_guard_pages[2],
        vm_resources.guard_page(),
    ];
    let host_pages = match HostPageTables::build(map, &mut arena, &guard_pages) {
        Ok(pages) => pages,
        Err(error) => {
            log_hex("hypewwisoww: host paging failed=", error as u64);
            halt_forever();
        }
    };
    log_hex("hypewwisoww: host CR3=", host_pages.root());
    log_hex("hypewwisoww: mapped 4K pages=", host_pages.mapped_4k_pages());
    log_hex("hypewwisoww: NX active=", host_pages.nx_enabled() as u64);
    unsafe { host_pages.activate() };
    log_line("hypewwisoww: host-owned page tables active");
    match vmx::enter_root(handoff.vmxon_region) {
        Ok(info) => {
            log_hex("hypewwisoww: VMX root active, revision=", info.revision_id as u64);
            log_line("hypewwisoww: launching EPT-backed 64-bit validation guest");
            if let Err(error) = vm::launch(&vm_resources, info) {
                log_hex("hypewwisoww: VMLAUNCH path failed=", error as u64);
                if let Some(instruction_error) = vm::instruction_error() {
                    log_hex("hypewwisoww: VM-instruction error=", instruction_error);
                }
                unsafe { vmx::leave_root() };
            }
        }
        Err(error) => {
            log_line("hypewwisoww: VMX entry failed");
            log_hex("hypewwisoww: VMX error=", error as u64);
        }
    }

    halt_forever()
}

fn fatal(message: &str) -> ! {
    log_line("hypewwisoww: fatal");
    log_line(message);
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    log_line("hypewwisoww: panic");
    if let Some(location) = info.location() {
        log_line(location.file());
        log_hex("hypewwisoww: line=", location.line() as u64);
    }
    halt_forever()
}
