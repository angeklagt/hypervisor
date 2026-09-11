use core::arch::asm;
use core::ptr;

use super::instructions::{cpuid, read_cr0, read_cr4, rdmsr, write_cr0, write_cr4, wrmsr};

const CPUID_FEATURES: u32 = 1;
const CPUID_ECX_VMX: u32 = 1 << 5;

const IA32_FEATURE_CONTROL: u32 = 0x0000_003a;
const FEATURE_CONTROL_LOCK: u64 = 1 << 0;
const FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;

const IA32_VMX_BASIC: u32 = 0x0000_0480;
const IA32_VMX_CR0_FIXED0: u32 = 0x0000_0486;
const IA32_VMX_CR0_FIXED1: u32 = 0x0000_0487;
const IA32_VMX_CR4_FIXED0: u32 = 0x0000_0488;
const IA32_VMX_CR4_FIXED1: u32 = 0x0000_0489;
const CR4_VMXE: u64 = 1 << 13;
const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;

#[repr(u64)]
#[derive(Clone, Copy, Debug)]
pub enum VmxError {
    Unsupported = 1,
    FirmwareDisabled = 2,
    InvalidBasicMsr = 3,
    RegionMisaligned = 4,
    InstructionFailed = 5,
    RegionAddressWidth = 6,
}

#[derive(Clone, Copy)]
pub struct VmxInfo {
    pub revision_id: u32,
    pub true_controls: bool,
    pub wide_physical_addresses: bool,
}

pub fn enter_root(vmxon_region: u64) -> Result<VmxInfo, VmxError> {
    if cpuid(CPUID_FEATURES, 0).ecx & CPUID_ECX_VMX == 0 {
        return Err(VmxError::Unsupported);
    }
    if vmxon_region & 0xfff != 0 {
        return Err(VmxError::RegionMisaligned);
    }
    let mut feature_control = unsafe { rdmsr(IA32_FEATURE_CONTROL) };
    if feature_control & FEATURE_CONTROL_LOCK != 0 {
        if feature_control & FEATURE_CONTROL_VMX_OUTSIDE_SMX == 0 {
            return Err(VmxError::FirmwareDisabled);
        }
    } else {
        feature_control |= FEATURE_CONTROL_LOCK | FEATURE_CONTROL_VMX_OUTSIDE_SMX;
        unsafe { wrmsr(IA32_FEATURE_CONTROL, feature_control) };
    }

    let basic = unsafe { rdmsr(IA32_VMX_BASIC) };
    let revision_id = (basic & 0x7fff_ffff) as u32;
    let region_size = ((basic >> 32) & 0x1fff) as usize;
    let memory_type = (basic >> 50) & 0x0f;
    if region_size == 0 || region_size > 4096 || memory_type != VMX_MEMORY_TYPE_WRITE_BACK {
        return Err(VmxError::InvalidBasicMsr);
    }
    if basic & (1 << 48) == 0 && vmxon_region > u64::from(u32::MAX) {
        return Err(VmxError::RegionAddressWidth);
    }

    unsafe {
        ptr::write_bytes(vmxon_region as *mut u8, 0, 4096);
        ptr::write_volatile(vmxon_region as *mut u32, revision_id);
    }

    let cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
    let cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };
    let cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
    let cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

    let cr0 = (read_cr0() | cr0_fixed0) & cr0_fixed1;
    let cr4 = (read_cr4() | cr4_fixed0 | CR4_VMXE) & cr4_fixed1;
    unsafe {
        write_cr0(cr0);
        write_cr4(cr4);
    }

    let operand = vmxon_region;
    let failed: u8;
    unsafe {
        asm!(
            "vmxon [{operand}]",
            "setna {failed}",
            operand = in(reg) &operand,
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed != 0 {
        return Err(VmxError::InstructionFailed);
    }

    Ok(VmxInfo {
        revision_id,
        true_controls: basic & (1 << 55) != 0,
        wide_physical_addresses: basic & (1 << 48) != 0,
    })
}

pub unsafe fn leave_root() {
    unsafe { asm!("vmxoff", options(nomem, nostack)) }
}
