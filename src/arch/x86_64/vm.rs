use core::arch::{asm, global_asm};
use core::mem::MaybeUninit;
use core::ptr;

use crate::boot_alloc::BootArena;
use crate::serial::{log_hex, log_line};

use super::instructions::{read_cr0, read_cr3, read_cr4, rdmsr};
use super::vmx::VmxInfo;

global_asm!(include_str!("vmexit.S"));

const PAGE_SIZE: usize = 4096;
const VMEXIT_STACK_PAGES: usize = 16;
const GUEST_PML4_GPA: u64 = 0x1000;
const GUEST_PDPT_GPA: u64 = 0x2000;
const GUEST_PD_GPA: u64 = 0x3000;
const GUEST_CODE_GPA: u64 = 0x4000;
const GUEST_STACK_GPA: u64 = 0x5000;
const GUEST_STACK_TOP: u64 = 0x6000;
const GUEST_MAGIC: u32 = 0xf00d_cafe;

const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;
const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48d;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48e;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48f;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
const IA32_EFER: u32 = 0xc000_0080;
const IA32_PAT: u32 = 0x277;
const IA32_FS_BASE: u32 = 0xc000_0100;
const IA32_GS_BASE: u32 = 0xc000_0101;
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;

const CPU_BASED_HLT_EXITING: u32 = 1 << 7;
const CPU_BASED_MOV_DR_EXITING: u32 = 1 << 23;
const CPU_BASED_UNCONDITIONAL_IO_EXITING: u32 = 1 << 24;
const CPU_BASED_ACTIVATE_SECONDARY: u32 = 1 << 31;
const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
const VM_EXIT_HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
const VM_EXIT_SAVE_EFER: u32 = 1 << 20;
const VM_EXIT_LOAD_EFER: u32 = 1 << 21;
const VM_ENTRY_IA32E_MODE: u32 = 1 << 9;
const VM_ENTRY_LOAD_EFER: u32 = 1 << 15;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const EPT_READ: u64 = 1 << 0;
const EPT_WRITE: u64 = 1 << 1;
const EPT_EXECUTE: u64 = 1 << 2;
const EPT_WRITE_BACK: u64 = 6 << 3;
const EPTP_PAGE_WALK_4: u64 = 3 << 3;
const EPT_CAP_PAGE_WALK_4: u64 = 1 << 6;
const EPT_CAP_WRITE_BACK: u64 = 1 << 14;

mod field {
    pub const GUEST_ES_SELECTOR: u64 = 0x0800;
    pub const GUEST_CS_SELECTOR: u64 = 0x0802;
    pub const GUEST_SS_SELECTOR: u64 = 0x0804;
    pub const GUEST_DS_SELECTOR: u64 = 0x0806;
    pub const GUEST_FS_SELECTOR: u64 = 0x0808;
    pub const GUEST_GS_SELECTOR: u64 = 0x080a;
    pub const GUEST_LDTR_SELECTOR: u64 = 0x080c;
    pub const GUEST_TR_SELECTOR: u64 = 0x080e;
    pub const HOST_ES_SELECTOR: u64 = 0x0c00;
    pub const HOST_CS_SELECTOR: u64 = 0x0c02;
    pub const HOST_SS_SELECTOR: u64 = 0x0c04;
    pub const HOST_DS_SELECTOR: u64 = 0x0c06;
    pub const HOST_FS_SELECTOR: u64 = 0x0c08;
    pub const HOST_GS_SELECTOR: u64 = 0x0c0a;
    pub const HOST_TR_SELECTOR: u64 = 0x0c0c;

    pub const EPT_POINTER: u64 = 0x201a;
    pub const GUEST_VMCS_LINK_POINTER: u64 = 0x2800;
    pub const GUEST_IA32_DEBUGCTL: u64 = 0x2802;
    pub const GUEST_IA32_PAT: u64 = 0x2804;
    pub const GUEST_IA32_EFER: u64 = 0x2806;
    pub const HOST_IA32_PAT: u64 = 0x2c00;
    pub const HOST_IA32_EFER: u64 = 0x2c02;

    pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x4000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x4002;
    pub const EXCEPTION_BITMAP: u64 = 0x4004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x4006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x4008;
    pub const CR3_TARGET_COUNT: u64 = 0x400a;
    pub const VM_EXIT_CONTROLS: u64 = 0x400c;
    pub const VM_EXIT_MSR_STORE_COUNT: u64 = 0x400e;
    pub const VM_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
    pub const VM_ENTRY_CONTROLS: u64 = 0x4012;
    pub const VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
    pub const VM_ENTRY_INTR_INFO_FIELD: u64 = 0x4016;
    pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x4018;
    pub const SECONDARY_VM_EXEC_CONTROL: u64 = 0x401e;
    pub const VM_INSTRUCTION_ERROR: u64 = 0x4400;
    pub const VM_EXIT_REASON: u64 = 0x4402;
    pub const VM_EXIT_INSTRUCTION_LEN: u64 = 0x440c;

    pub const GUEST_ES_LIMIT: u64 = 0x4800;
    pub const GUEST_CS_LIMIT: u64 = 0x4802;
    pub const GUEST_SS_LIMIT: u64 = 0x4804;
    pub const GUEST_DS_LIMIT: u64 = 0x4806;
    pub const GUEST_FS_LIMIT: u64 = 0x4808;
    pub const GUEST_GS_LIMIT: u64 = 0x480a;
    pub const GUEST_LDTR_LIMIT: u64 = 0x480c;
    pub const GUEST_TR_LIMIT: u64 = 0x480e;
    pub const GUEST_GDTR_LIMIT: u64 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u64 = 0x4812;
    pub const GUEST_ES_AR_BYTES: u64 = 0x4814;
    pub const GUEST_CS_AR_BYTES: u64 = 0x4816;
    pub const GUEST_SS_AR_BYTES: u64 = 0x4818;
    pub const GUEST_DS_AR_BYTES: u64 = 0x481a;
    pub const GUEST_FS_AR_BYTES: u64 = 0x481c;
    pub const GUEST_GS_AR_BYTES: u64 = 0x481e;
    pub const GUEST_LDTR_AR_BYTES: u64 = 0x4820;
    pub const GUEST_TR_AR_BYTES: u64 = 0x4822;
    pub const GUEST_INTERRUPTIBILITY_INFO: u64 = 0x4824;
    pub const GUEST_ACTIVITY_STATE: u64 = 0x4826;
    pub const GUEST_SYSENTER_CS: u64 = 0x482a;
    pub const HOST_IA32_SYSENTER_CS: u64 = 0x4c00;

    pub const CR0_GUEST_HOST_MASK: u64 = 0x6000;
    pub const CR4_GUEST_HOST_MASK: u64 = 0x6002;
    pub const CR0_READ_SHADOW: u64 = 0x6004;
    pub const CR4_READ_SHADOW: u64 = 0x6006;
    pub const EXIT_QUALIFICATION: u64 = 0x6400;
    pub const GUEST_CR0: u64 = 0x6800;
    pub const GUEST_CR3: u64 = 0x6802;
    pub const GUEST_CR4: u64 = 0x6804;
    pub const GUEST_ES_BASE: u64 = 0x6806;
    pub const GUEST_CS_BASE: u64 = 0x6808;
    pub const GUEST_SS_BASE: u64 = 0x680a;
    pub const GUEST_DS_BASE: u64 = 0x680c;
    pub const GUEST_FS_BASE: u64 = 0x680e;
    pub const GUEST_GS_BASE: u64 = 0x6810;
    pub const GUEST_LDTR_BASE: u64 = 0x6812;
    pub const GUEST_TR_BASE: u64 = 0x6814;
    pub const GUEST_GDTR_BASE: u64 = 0x6816;
    pub const GUEST_IDTR_BASE: u64 = 0x6818;
    pub const GUEST_DR7: u64 = 0x681a;
    pub const GUEST_RSP: u64 = 0x681c;
    pub const GUEST_RIP: u64 = 0x681e;
    pub const GUEST_RFLAGS: u64 = 0x6820;
    pub const GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x6822;
    pub const GUEST_SYSENTER_ESP: u64 = 0x6824;
    pub const GUEST_SYSENTER_EIP: u64 = 0x6826;
    pub const HOST_CR0: u64 = 0x6c00;
    pub const HOST_CR3: u64 = 0x6c02;
    pub const HOST_CR4: u64 = 0x6c04;
    pub const HOST_FS_BASE: u64 = 0x6c06;
    pub const HOST_GS_BASE: u64 = 0x6c08;
    pub const HOST_TR_BASE: u64 = 0x6c0a;
    pub const HOST_GDTR_BASE: u64 = 0x6c0c;
    pub const HOST_IDTR_BASE: u64 = 0x6c0e;
    pub const HOST_IA32_SYSENTER_ESP: u64 = 0x6c10;
    pub const HOST_IA32_SYSENTER_EIP: u64 = 0x6c12;
    pub const HOST_RSP: u64 = 0x6c14;
    pub const HOST_RIP: u64 = 0x6c16;
}

#[derive(Clone, Copy, Debug)]
pub enum VmError {
    ArenaExhausted,
    VmcsAddressWidth,
    VmclearFailed,
    VmptrldFailed,
    VmwriteFailed,
    ControlUnavailable,
    EptUnavailable,
    VmlaunchFailed,
    VmreadFailed,
}

pub struct VmResources {
    vmcs: u64,
    vmexit_stack_top: u64,
    vmexit_guard: u64,
    ept_root: u64,
}

impl VmResources {
    pub fn allocate(arena: &mut BootArena) -> Result<Self, VmError> {
        let vmcs = page(arena)?;
        let vmexit_stack = pages(arena, VMEXIT_STACK_PAGES + 1)?;
        let vmexit_guard = vmexit_stack;
        let vmexit_stack_top =
            vmexit_stack + ((VMEXIT_STACK_PAGES + 1) * PAGE_SIZE) as u64;

        let guest_pml4 = page(arena)?;
        let guest_pdpt = page(arena)?;
        let guest_pd = page(arena)?;
        let guest_code = page(arena)?;
        let guest_stack = page(arena)?;
        unsafe {
            write_entry(guest_pml4, 0, GUEST_PDPT_GPA | 0x3);
            write_entry(guest_pdpt, 0, GUEST_PD_GPA | 0x3);
            write_entry(guest_pd, 0, 0x83);
        }

        // mov eax, 0xf00dcafe; vmcall; hlt
        const GUEST_CODE: [u8; 9] = [
            0xb8, 0xfe, 0xca, 0x0d, 0xf0, 0x0f, 0x01, 0xc1, 0xf4,
        ];
        unsafe {
            ptr::copy_nonoverlapping(GUEST_CODE.as_ptr(), guest_code as *mut u8, GUEST_CODE.len());
        }

        let ept_pml4 = page(arena)?;
        let ept_pdpt = page(arena)?;
        let ept_pd = page(arena)?;
        let ept_pt = page(arena)?;
        let nonleaf = EPT_READ | EPT_WRITE | EPT_EXECUTE;
        unsafe {
            write_entry(ept_pml4, 0, ept_pdpt | nonleaf);
            write_entry(ept_pdpt, 0, ept_pd | nonleaf);
            write_entry(ept_pd, 0, ept_pt | nonleaf);
            ept_map(ept_pt, GUEST_PML4_GPA, guest_pml4, EPT_READ | EPT_WRITE);
            ept_map(ept_pt, GUEST_PDPT_GPA, guest_pdpt, EPT_READ | EPT_WRITE);
            ept_map(ept_pt, GUEST_PD_GPA, guest_pd, EPT_READ | EPT_WRITE);
            ept_map(ept_pt, GUEST_CODE_GPA, guest_code, EPT_READ | EPT_EXECUTE);
            ept_map(ept_pt, GUEST_STACK_GPA, guest_stack, EPT_READ | EPT_WRITE);
        }

        Ok(Self {
            vmcs,
            vmexit_stack_top,
            vmexit_guard,
            ept_root: ept_pml4,
        })
    }

    pub fn guard_page(&self) -> u64 {
        self.vmexit_guard
    }
}

pub fn launch(resources: &VmResources, info: VmxInfo) -> Result<(), VmError> {
    if !info.wide_physical_addresses && resources.vmcs > u64::from(u32::MAX) {
        return Err(VmError::VmcsAddressWidth);
    }
    unsafe { (resources.vmcs as *mut u32).write_volatile(info.revision_id) };
    vmclear(resources.vmcs)?;
    vmptrld(resources.vmcs)?;

    write_controls(resources, info.true_controls)?;
    write_guest_state()?;
    write_host_state(resources)?;

    let failed: u8;
    unsafe {
        asm!(
            "vmlaunch",
            "setna {failed}",
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed != 0 {
        return Err(VmError::VmlaunchFailed);
    }
    Ok(())
}

pub fn instruction_error() -> Option<u64> {
    vmread(field::VM_INSTRUCTION_ERROR).ok()
}

fn write_controls(resources: &VmResources, true_controls: bool) -> Result<(), VmError> {
    let pin_msr = if true_controls {
        IA32_VMX_TRUE_PINBASED_CTLS
    } else {
        IA32_VMX_PINBASED_CTLS
    };
    let primary_msr = if true_controls {
        IA32_VMX_TRUE_PROCBASED_CTLS
    } else {
        IA32_VMX_PROCBASED_CTLS
    };
    let exit_msr = if true_controls {
        IA32_VMX_TRUE_EXIT_CTLS
    } else {
        IA32_VMX_EXIT_CTLS
    };
    let entry_msr = if true_controls {
        IA32_VMX_TRUE_ENTRY_CTLS
    } else {
        IA32_VMX_ENTRY_CTLS
    };

    let pin = adjusted_controls(0, pin_msr);
    let primary_desired = CPU_BASED_HLT_EXITING
        | CPU_BASED_MOV_DR_EXITING
        | CPU_BASED_UNCONDITIONAL_IO_EXITING
        | CPU_BASED_ACTIVATE_SECONDARY;
    let primary = adjusted_controls(primary_desired, primary_msr);
    let secondary = adjusted_controls(SECONDARY_ENABLE_EPT, IA32_VMX_PROCBASED_CTLS2);
    let exit_desired =
        VM_EXIT_HOST_ADDRESS_SPACE_SIZE | VM_EXIT_SAVE_EFER | VM_EXIT_LOAD_EFER;
    let exit = adjusted_controls(exit_desired, exit_msr);
    let entry_desired = VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_EFER;
    let entry = adjusted_controls(entry_desired, entry_msr);

    if primary & CPU_BASED_ACTIVATE_SECONDARY == 0
        || secondary & SECONDARY_ENABLE_EPT == 0
        || exit & exit_desired != exit_desired
        || entry & entry_desired != entry_desired
    {
        return Err(VmError::ControlUnavailable);
    }
    let ept_cap = unsafe { rdmsr(IA32_VMX_EPT_VPID_CAP) };
    if ept_cap & EPT_CAP_PAGE_WALK_4 == 0 || ept_cap & EPT_CAP_WRITE_BACK == 0 {
        return Err(VmError::EptUnavailable);
    }

    vmwrite(field::PIN_BASED_VM_EXEC_CONTROL, u64::from(pin))?;
    vmwrite(field::CPU_BASED_VM_EXEC_CONTROL, u64::from(primary))?;
    vmwrite(field::SECONDARY_VM_EXEC_CONTROL, u64::from(secondary))?;
    vmwrite(field::VM_EXIT_CONTROLS, u64::from(exit))?;
    vmwrite(field::VM_ENTRY_CONTROLS, u64::from(entry))?;
    vmwrite(field::EXCEPTION_BITMAP, 0)?;
    vmwrite(field::PAGE_FAULT_ERROR_CODE_MASK, 0)?;
    vmwrite(field::PAGE_FAULT_ERROR_CODE_MATCH, 0)?;
    vmwrite(field::CR3_TARGET_COUNT, 0)?;
    vmwrite(field::VM_EXIT_MSR_STORE_COUNT, 0)?;
    vmwrite(field::VM_EXIT_MSR_LOAD_COUNT, 0)?;
    vmwrite(field::VM_ENTRY_MSR_LOAD_COUNT, 0)?;
    vmwrite(field::VM_ENTRY_INTR_INFO_FIELD, 0)?;
    vmwrite(field::CR0_GUEST_HOST_MASK, 0)?;
    vmwrite(field::CR4_GUEST_HOST_MASK, 0)?;
    vmwrite(field::CR0_READ_SHADOW, 0)?;
    vmwrite(field::CR4_READ_SHADOW, 0)?;

    let eptp = resources.ept_root | EPT_WRITE_BACK | EPTP_PAGE_WALK_4;
    vmwrite(field::EPT_POINTER, eptp)
}

fn write_guest_state() -> Result<(), VmError> {
    // VMX fixed bits apply to guest CR0/CR4 when unrestricted guest is off
    let desired_cr0 =
        (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) | (1 << 16) | (1 << 31);
    let desired_cr4 = 1 << 5; // PAE, with LA57/PCID/SMEP/SMAP/CET intentionally off
    let cr0 = (desired_cr0 | unsafe { rdmsr(IA32_VMX_CR0_FIXED0) })
        & unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };
    let cr4 = (desired_cr4 | unsafe { rdmsr(IA32_VMX_CR4_FIXED0) })
        & unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };
    let efer = unsafe { rdmsr(IA32_EFER) } | EFER_LME | EFER_LMA;

    vmwrite(field::GUEST_CR0, cr0)?;
    vmwrite(field::GUEST_CR3, GUEST_PML4_GPA)?;
    vmwrite(field::GUEST_CR4, cr4)?;
    vmwrite(field::GUEST_DR7, 0x400)?;
    vmwrite(field::GUEST_RSP, GUEST_STACK_TOP)?;
    vmwrite(field::GUEST_RIP, GUEST_CODE_GPA)?;
    vmwrite(field::GUEST_RFLAGS, 0x2)?;
    vmwrite(field::GUEST_PENDING_DBG_EXCEPTIONS, 0)?;
    vmwrite(field::GUEST_VMCS_LINK_POINTER, u64::MAX)?;
    vmwrite(field::GUEST_IA32_DEBUGCTL, 0)?;
    vmwrite(field::GUEST_IA32_PAT, unsafe { rdmsr(IA32_PAT) })?;
    vmwrite(field::GUEST_IA32_EFER, efer)?;

    write_guest_segment(
        field::GUEST_ES_SELECTOR,
        field::GUEST_ES_BASE,
        field::GUEST_ES_LIMIT,
        field::GUEST_ES_AR_BYTES,
        0x10,
        0,
        0xffff_ffff,
        0xc093,
    )?;
    write_guest_segment(
        field::GUEST_CS_SELECTOR,
        field::GUEST_CS_BASE,
        field::GUEST_CS_LIMIT,
        field::GUEST_CS_AR_BYTES,
        0x08,
        0,
        0xffff_ffff,
        0xa09b,
    )?;
    write_guest_segment(
        field::GUEST_SS_SELECTOR,
        field::GUEST_SS_BASE,
        field::GUEST_SS_LIMIT,
        field::GUEST_SS_AR_BYTES,
        0x10,
        0,
        0xffff_ffff,
        0xc093,
    )?;
    write_guest_segment(
        field::GUEST_DS_SELECTOR,
        field::GUEST_DS_BASE,
        field::GUEST_DS_LIMIT,
        field::GUEST_DS_AR_BYTES,
        0x10,
        0,
        0xffff_ffff,
        0xc093,
    )?;
    write_guest_segment(
        field::GUEST_FS_SELECTOR,
        field::GUEST_FS_BASE,
        field::GUEST_FS_LIMIT,
        field::GUEST_FS_AR_BYTES,
        0x10,
        0,
        0xffff_ffff,
        0xc093,
    )?;
    write_guest_segment(
        field::GUEST_GS_SELECTOR,
        field::GUEST_GS_BASE,
        field::GUEST_GS_LIMIT,
        field::GUEST_GS_AR_BYTES,
        0x10,
        0,
        0xffff_ffff,
        0xc093,
    )?;
    write_guest_segment(
        field::GUEST_LDTR_SELECTOR,
        field::GUEST_LDTR_BASE,
        field::GUEST_LDTR_LIMIT,
        field::GUEST_LDTR_AR_BYTES,
        0,
        0,
        0,
        1 << 16,
    )?;
    write_guest_segment(
        field::GUEST_TR_SELECTOR,
        field::GUEST_TR_BASE,
        field::GUEST_TR_LIMIT,
        field::GUEST_TR_AR_BYTES,
        0x18,
        0,
        0x67,
        0x008b,
    )?;

    vmwrite(field::GUEST_GDTR_BASE, 0)?;
    vmwrite(field::GUEST_GDTR_LIMIT, 0)?;
    vmwrite(field::GUEST_IDTR_BASE, 0)?;
    vmwrite(field::GUEST_IDTR_LIMIT, 0)?;
    vmwrite(field::GUEST_INTERRUPTIBILITY_INFO, 0)?;
    vmwrite(field::GUEST_ACTIVITY_STATE, 0)?;
    vmwrite(field::GUEST_SYSENTER_CS, 0)?;
    vmwrite(field::GUEST_SYSENTER_ESP, 0)?;
    vmwrite(field::GUEST_SYSENTER_EIP, 0)
}

#[allow(clippy::too_many_arguments)]
fn write_guest_segment(
    selector_field: u64,
    base_field: u64,
    limit_field: u64,
    access_field: u64,
    selector: u16,
    base: u64,
    limit: u32,
    access: u32,
) -> Result<(), VmError> {
    vmwrite(selector_field, u64::from(selector))?;
    vmwrite(base_field, base)?;
    vmwrite(limit_field, u64::from(limit))?;
    vmwrite(access_field, u64::from(access))
}

fn write_host_state(resources: &VmResources) -> Result<(), VmError> {
    let gdtr = read_gdtr();
    let idtr = read_idtr();
    vmwrite(field::HOST_CR0, read_cr0())?;
    vmwrite(field::HOST_CR3, read_cr3())?;
    vmwrite(field::HOST_CR4, read_cr4())?;
    vmwrite(field::HOST_ES_SELECTOR, u64::from(read_es() & !7))?;
    vmwrite(field::HOST_CS_SELECTOR, u64::from(read_cs() & !7))?;
    vmwrite(field::HOST_SS_SELECTOR, u64::from(read_ss() & !7))?;
    vmwrite(field::HOST_DS_SELECTOR, u64::from(read_ds() & !7))?;
    vmwrite(field::HOST_FS_SELECTOR, u64::from(read_fs() & !7))?;
    vmwrite(field::HOST_GS_SELECTOR, u64::from(read_gs() & !7))?;
    vmwrite(field::HOST_TR_SELECTOR, u64::from(read_tr() & !7))?;
    vmwrite(field::HOST_FS_BASE, unsafe { rdmsr(IA32_FS_BASE) })?;
    vmwrite(field::HOST_GS_BASE, unsafe { rdmsr(IA32_GS_BASE) })?;
    vmwrite(field::HOST_TR_BASE, super::descriptors::host_tss_base())?;
    vmwrite(field::HOST_GDTR_BASE, gdtr.base)?;
    vmwrite(field::HOST_IDTR_BASE, idtr.base)?;
    vmwrite(field::HOST_IA32_PAT, unsafe { rdmsr(IA32_PAT) })?;
    vmwrite(field::HOST_IA32_EFER, unsafe { rdmsr(IA32_EFER) })?;
    vmwrite(field::HOST_IA32_SYSENTER_CS, unsafe { rdmsr(IA32_SYSENTER_CS) })?;
    vmwrite(field::HOST_IA32_SYSENTER_ESP, unsafe { rdmsr(IA32_SYSENTER_ESP) })?;
    vmwrite(field::HOST_IA32_SYSENTER_EIP, unsafe { rdmsr(IA32_SYSENTER_EIP) })?;
    vmwrite(field::HOST_RSP, resources.vmexit_stack_top)?;
    vmwrite(field::HOST_RIP, ptr::addr_of!(vmexit_entry) as u64)
}

fn adjusted_controls(desired: u32, capability_msr: u32) -> u32 {
    let capability = unsafe { rdmsr(capability_msr) };
    let must_be_one = capability as u32;
    let may_be_one = (capability >> 32) as u32;
    (desired | must_be_one) & may_be_one
}

fn vmclear(vmcs: u64) -> Result<(), VmError> {
    let failed: u8;
    unsafe {
        asm!(
            "vmclear [{operand}]",
            "setna {failed}",
            operand = in(reg) &vmcs,
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(VmError::VmclearFailed)
    }
}

fn vmptrld(vmcs: u64) -> Result<(), VmError> {
    let failed: u8;
    unsafe {
        asm!(
            "vmptrld [{operand}]",
            "setna {failed}",
            operand = in(reg) &vmcs,
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(VmError::VmptrldFailed)
    }
}

fn vmwrite(field: u64, value: u64) -> Result<(), VmError> {
    let failed: u8;
    unsafe {
        asm!(
            "vmwrite {field}, {value}",
            "setna {failed}",
            value = in(reg) value,
            field = in(reg) field,
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(VmError::VmwriteFailed)
    }
}

fn vmread(field: u64) -> Result<u64, VmError> {
    let value: u64;
    let failed: u8;
    unsafe {
        asm!(
            "vmread {value}, {field}",
            "setna {failed}",
            field = in(reg) field,
            value = lateout(reg) value,
            failed = lateout(reg_byte) failed,
            options(nostack)
        )
    }
    if failed == 0 {
        Ok(value)
    } else {
        Err(VmError::VmreadFailed)
    }
}

fn page(arena: &mut BootArena) -> Result<u64, VmError> {
    pages(arena, 1)
}

fn pages(arena: &mut BootArena, count: usize) -> Result<u64, VmError> {
    arena
        .allocate_pages(count)
        .map(|page| page.as_ptr() as u64)
        .ok_or(VmError::ArenaExhausted)
}

unsafe fn write_entry(table: u64, index: usize, value: u64) {
    debug_assert!(index < 512);
    unsafe { (table as *mut u64).add(index).write(value) }
}

unsafe fn ept_map(table: u64, guest: u64, host: u64, permissions: u64) {
    let index = (guest >> 12) as usize & 0x1ff;
    unsafe { write_entry(table, index, host | permissions | EPT_WRITE_BACK) }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

fn read_gdtr() -> DescriptorTablePointer {
    let mut pointer = MaybeUninit::<DescriptorTablePointer>::uninit();
    unsafe { asm!("sgdt [{0}]", in(reg) pointer.as_mut_ptr(), options(nostack)) };
    unsafe { pointer.assume_init() }
}

fn read_idtr() -> DescriptorTablePointer {
    let mut pointer = MaybeUninit::<DescriptorTablePointer>::uninit();
    unsafe { asm!("sidt [{0}]", in(reg) pointer.as_mut_ptr(), options(nostack)) };
    unsafe { pointer.assume_init() }
}

macro_rules! segment_reader {
    ($name:ident, $instruction:literal) => {
        fn $name() -> u16 {
            let value: u16;
            unsafe { asm!($instruction, out(reg) value, options(nomem, nostack)) };
            value
        }
    };
}

segment_reader!(read_cs, "mov {0:x}, cs");
segment_reader!(read_ss, "mov {0:x}, ss");
segment_reader!(read_ds, "mov {0:x}, ds");
segment_reader!(read_es, "mov {0:x}, es");
segment_reader!(read_fs, "mov {0:x}, fs");
segment_reader!(read_gs, "mov {0:x}, gs");

fn read_tr() -> u16 {
    let value: u16;
    unsafe { asm!("str {0:x}", out(reg) value, options(nomem, nostack)) };
    value
}

unsafe extern "C" {
    static vmexit_entry: u8;
}

#[repr(C)]
struct GuestRegisters {
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
}

#[unsafe(no_mangle)]
extern "sysv64" fn vmexit_dispatch(registers: *mut GuestRegisters) {
    log_line("hypewwisoww: VM exit");
    let reason = vmread(field::VM_EXIT_REASON).unwrap_or(u64::MAX);
    let rip = vmread(field::GUEST_RIP).unwrap_or(u64::MAX);
    let length = vmread(field::VM_EXIT_INSTRUCTION_LEN).unwrap_or(0);
    let qualification = vmread(field::EXIT_QUALIFICATION).unwrap_or(u64::MAX);
    log_hex("hypewwisoww: exit reason=", reason);
    log_hex("hypewwisoww: guest RIP=", rip);
    log_hex("hypewwisoww: instruction length=", length);
    log_hex("hypewwisoww: qualification=", qualification);

    if registers.is_null() {
        stop("hypewwisoww: null VM-exit register frame");
    }
    let registers = unsafe { &mut *registers };
    log_hex("hypewwisoww: guest RAX=", registers.rax);

    match reason & 0xffff {
        10 => handle_cpuid(registers),
        12 => stop("hypewwisoww: guest halted"),
        18 => {
            if registers.rax as u32 == GUEST_MAGIC {
                stop("hypewwisoww: synthetic 64-bit guest VMCALL verified");
            }
            registers.rax = u64::MAX;
            advance_guest_rip();
        }
        23 | 25 => inject_general_protection(),
        28 => stop("hypewwisoww: unimplemented control-register exit"),
        30 => handle_io(registers, qualification),
        31 => handle_rdmsr(registers),
        32 => handle_wrmsr(registers),
        48 => stop("hypewwisoww: fatal EPT violation"),
        _ => stop("hypewwisoww: unsupported VM exit"),
    }
}

fn handle_cpuid(registers: &mut GuestRegisters) {
    let leaf = registers.rax as u32;
    let subleaf = registers.rcx as u32;
    let (eax, ebx, ecx, edx) = match leaf {
        0x4000_0000 => (0x4000_0001, 0x7272_6546, 0x7369_766f, 0x2020_726f),
        0x4000_0001 => (0x3123_7646, 0, 0, 0),
        _ => {
            let result = super::instructions::cpuid(leaf, subleaf);
            let mut ecx = result.ecx;
            if leaf == 1 {
                ecx = (ecx & !(1 << 5)) | (1 << 31); // Hide VMX; expose hypervisor.
            }
            if leaf == 0x8000_0001 {
                ecx &= !(1 << 2); // Hide AMD SVM if this path is ever reused.
            }
            (result.eax, result.ebx, ecx, result.edx)
        }
    };
    registers.rax = u64::from(eax);
    registers.rbx = u64::from(ebx);
    registers.rcx = u64::from(ecx);
    registers.rdx = u64::from(edx);
    advance_guest_rip();
}

fn handle_io(registers: &mut GuestRegisters, qualification: u64) {
    let width = (qualification & 0x7) + 1;
    let input = qualification & (1 << 3) != 0;
    let string = qualification & (1 << 4) != 0;
    let repeated = qualification & (1 << 5) != 0;
    if string || repeated || !matches!(width, 1 | 2 | 4) {
        inject_general_protection();
        return;
    }
    if input {
        let mask = match width {
            1 => 0xff,
            2 => 0xffff,
            _ => 0xffff_ffff,
        };
        registers.rax = (registers.rax & !mask) | mask;
    }
    advance_guest_rip();
}

fn handle_rdmsr(registers: &mut GuestRegisters) {
    let value = match registers.rcx as u32 {
        IA32_EFER => vmread(field::GUEST_IA32_EFER),
        IA32_PAT => vmread(field::GUEST_IA32_PAT),
        IA32_FS_BASE => vmread(field::GUEST_FS_BASE),
        IA32_GS_BASE => vmread(field::GUEST_GS_BASE),
        _ => {
            inject_general_protection();
            return;
        }
    };
    let Ok(value) = value else {
        stop("hypewwisoww: VMREAD failed during RDMSR emulation");
    };
    registers.rax = value as u32 as u64;
    registers.rdx = (value >> 32) as u32 as u64;
    advance_guest_rip();
}

fn handle_wrmsr(registers: &GuestRegisters) {
    let value = (registers.rdx as u32 as u64) << 32 | registers.rax as u32 as u64;
    let result = match registers.rcx as u32 {
        IA32_FS_BASE if is_canonical(value) => vmwrite(field::GUEST_FS_BASE, value),
        IA32_GS_BASE if is_canonical(value) => vmwrite(field::GUEST_GS_BASE, value),
        IA32_EFER => {
            let current = vmread(field::GUEST_IA32_EFER).unwrap_or(0);
            let allowed = (1 << 0) | (1 << 11);
            if value & !(allowed | EFER_LME | EFER_LMA) != 0
                || value & (EFER_LME | EFER_LMA) != (EFER_LME | EFER_LMA)
            {
                inject_general_protection();
                return;
            }
            vmwrite(
                field::GUEST_IA32_EFER,
                (current & !(allowed)) | (value & allowed) | EFER_LME | EFER_LMA,
            )
        }
        _ => {
            inject_general_protection();
            return;
        }
    };
    if result.is_err() {
        stop("hypewwisoww: VMWRITE failed during WRMSR emulation");
    }
    advance_guest_rip();
}

fn advance_guest_rip() {
    let rip = vmread(field::GUEST_RIP).unwrap_or_else(|_| {
        stop("hypewwisoww: cannot read guest RIP");
    });
    let length = vmread(field::VM_EXIT_INSTRUCTION_LEN).unwrap_or_else(|_| {
        stop("hypewwisoww: cannot read VM-exit instruction length");
    });
    if vmwrite(field::GUEST_RIP, rip.wrapping_add(length)).is_err() {
        stop("hypewwisoww: cannot advance guest RIP");
    }
}

fn inject_general_protection() {
    const VALID: u64 = 1 << 31;
    const DELIVER_ERROR_CODE: u64 = 1 << 11;
    const HARDWARE_EXCEPTION: u64 = 3 << 8;
    const GENERAL_PROTECTION: u64 = 13;
    if vmwrite(
        field::VM_ENTRY_INTR_INFO_FIELD,
        VALID | DELIVER_ERROR_CODE | HARDWARE_EXCEPTION | GENERAL_PROTECTION,
    )
    .is_err()
        || vmwrite(field::VM_ENTRY_EXCEPTION_ERROR_CODE, 0).is_err()
    {
        stop("hypewwisoww: failed to inject #GP");
    }
}

fn is_canonical(value: u64) -> bool {
    let upper = value >> 48;
    upper == 0 || upper == 0xffff
}

fn stop(message: &str) -> ! {
    log_line(message);
    unsafe { asm!("vmxoff", options(nomem, nostack)) };
    loop {
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) }
    }
}

#[unsafe(no_mangle)]
extern "sysv64" fn vmresume_failed() -> ! {
    log_line("hypewwisoww: VMRESUME failed");
    if let Some(error) = instruction_error() {
        log_hex("hypewwisoww: VM-instruction error=", error);
    }
    stop("hypewwisoww: stopping after VMRESUME failure")
}
