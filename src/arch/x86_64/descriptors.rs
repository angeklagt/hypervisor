use core::arch::{asm, global_asm};
use core::mem;
use core::ptr;

use crate::boot_alloc::BootArena;
use crate::serial::{log_hex, log_line};

global_asm!(include_str!("exceptions.S"));

const GDT_ENTRIES: usize = 5;
const IDT_ENTRIES: usize = 256;
const EXCEPTION_COUNT: usize = 32;
const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;
const IST_STACK_PAGES: usize = 8;
const STACK_GUARD_PAGES: usize = 1;

static mut GDT: [u64; GDT_ENTRIES] = [0; GDT_ENTRIES];
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::missing(); IDT_ENTRIES];
static mut TSS: TaskStateSegment = TaskStateSegment::empty();

unsafe extern "C" {
    static isr_stub_table: u8;
    static isr_unhandled: u8;
}

#[derive(Clone, Copy, Debug)]
pub enum DescriptorError {
    ArenaExhausted,
}

pub struct DescriptorState {
    pub ist_guard_pages: [u64; 3],
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x07,
            attributes: 0x8e,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C)]
struct TaskStateSegment {
    bytes: [u8; 104],
}

impl TaskStateSegment {
    const fn empty() -> Self {
        Self { bytes: [0; 104] }
    }

    fn set_rsp0(&mut self, value: u64) {
        self.write_u64(4, value);
    }

    fn set_ist(&mut self, index: usize, value: u64) {
        debug_assert!(index < 7);
        self.write_u64(36 + index * 8, value);
    }

    fn disable_io_bitmap(&mut self) {
        self.write_u16(102, mem::size_of::<Self>() as u16);
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

const _: () = assert!(mem::size_of::<IdtEntry>() == 16);
const _: () = assert!(mem::size_of::<TaskStateSegment>() == 104);

pub fn host_tss_base() -> u64 {
    ptr::addr_of!(TSS) as u64
}

pub unsafe fn install(
    arena: &mut BootArena,
    kernel_stack_top: u64,
) -> Result<DescriptorState, DescriptorError> {
    let (double_fault_stack, double_fault_guard) = stack_top(arena)?;
    let (nmi_stack, nmi_guard) = stack_top(arena)?;
    let (machine_check_stack, machine_check_guard) = stack_top(arena)?;

    let mut tss = TaskStateSegment::empty();
    tss.set_rsp0(kernel_stack_top);
    tss.set_ist(0, double_fault_stack);
    tss.set_ist(1, nmi_stack);
    tss.set_ist(2, machine_check_stack);
    tss.disable_io_bitmap();
    unsafe { ptr::write(ptr::addr_of_mut!(TSS), tss) };

    let tss_base = ptr::addr_of!(TSS) as u64;
    let (tss_low, tss_high) = tss_descriptor(tss_base, (mem::size_of::<TaskStateSegment>() - 1) as u32);
    let gdt = ptr::addr_of_mut!(GDT).cast::<u64>();
    unsafe {
        gdt.add(0).write(0);
        gdt.add(1).write(0x00af_9a00_0000_ffff);
        gdt.add(2).write(0x00cf_9200_0000_ffff);
        gdt.add(3).write(tss_low);
        gdt.add(4).write(tss_high);
    }

    let stub_table = ptr::addr_of!(isr_stub_table).cast::<usize>();
    let unhandled = ptr::addr_of!(isr_unhandled) as u64;
    let idt = ptr::addr_of_mut!(IDT).cast::<IdtEntry>();
    for vector in 0..IDT_ENTRIES {
        let handler = if vector < EXCEPTION_COUNT {
            unsafe { stub_table.add(vector).read() as u64 }
        } else {
            unhandled
        };
        let ist = match vector {
            2 => 2,  // NMI
            8 => 1,  // Double fault
            18 => 3, // Machine check
            _ => 0,
        };
        // SAFETY: vector is within the 256-entry static IDT.
        unsafe { idt.add(vector).write(IdtEntry::interrupt_gate(handler, ist)) };
    }

    let gdtr = DescriptorTablePointer {
        limit: (mem::size_of::<[u64; GDT_ENTRIES]>() - 1) as u16,
        base: ptr::addr_of!(GDT) as u64,
    };
    let idtr = DescriptorTablePointer {
        limit: (mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: ptr::addr_of!(IDT) as u64,
    };

    unsafe {
        load_gdt_and_tss(&gdtr);
        asm!("lidt [{0}]", in(reg) &idtr, options(readonly, nostack));
    }
    Ok(DescriptorState {
        ist_guard_pages: [double_fault_guard, nmi_guard, machine_check_guard],
    })
}

fn stack_top(arena: &mut BootArena) -> Result<(u64, u64), DescriptorError> {
    let stack = arena
        .allocate_pages(IST_STACK_PAGES + STACK_GUARD_PAGES)
        .ok_or(DescriptorError::ArenaExhausted)?;
    let guard = stack.as_ptr() as u64;
    let top = guard + ((IST_STACK_PAGES + STACK_GUARD_PAGES) * 4096) as u64;
    Ok((top, guard))
}

fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let low = u64::from(limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x9u64 << 40)
        | (1u64 << 47)
        | (u64::from((limit >> 16) & 0x0f) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

unsafe fn load_gdt_and_tss(gdtr: &DescriptorTablePointer) {
    unsafe {
        asm!(
            "lgdt [{gdtr}]",
            "push {code}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {data}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor eax, eax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ax, {tss}",
            "ltr ax",
            gdtr = in(reg) gdtr,
            code = const KERNEL_CODE_SELECTOR,
            data = const KERNEL_DATA_SELECTOR,
            tss = const TSS_SELECTOR,
            out("rax") _,
        )
    }
}

#[repr(C)]
pub struct ExceptionFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
}

#[unsafe(no_mangle)]
extern "sysv64" fn exception_dispatch(frame: *const ExceptionFrame) -> ! {
    log_line("hypewwisoww: host exception");
    if frame.is_null() {
        log_line("hypewwisoww: missing exception frame");
    } else {
        let frame = unsafe { &*frame };
        log_hex("hypewwisoww: vector=", frame.vector);
        log_hex("hypewwisoww: error=", frame.error_code);
        log_hex("hypewwisoww: rip=", frame.rip);
        log_hex("hypewwisoww: rflags=", frame.rflags);
        log_hex("hypewwisoww: cr2=", super::instructions::read_cr2());
    }
    loop {
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) }
    }
}
