use core::arch::asm;

pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
    CpuidResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[derive(Clone, Copy)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        )
    }
    u64::from(low) | (u64::from(high) << 32)
}

pub unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack)
        )
    }
}

pub fn read_cr0() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack)) };
    value
}

pub unsafe fn write_cr0(value: u64) {
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nomem, nostack)) }
}

pub fn read_cr2() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack)) };
    value
}

pub fn read_cr4() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack)) };
    value
}

pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack)) };
    value
}

pub unsafe fn write_cr4(value: u64) {
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nomem, nostack)) }
}

pub unsafe fn write_cr3(value: u64) {
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack)) }
}
