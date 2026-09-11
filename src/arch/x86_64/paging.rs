use core::ptr;

use crate::boot_alloc::BootArena;
use crate::memory::MemoryMap;

use super::instructions::{cpuid, read_cr0, rdmsr, write_cr0, write_cr3, wrmsr};

const PAGE_SIZE: u64 = 4096;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const ENTRY_COUNT: usize = 512;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const CR0_WRITE_PROTECT: u64 = 1 << 16;
const IA32_EFER: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_EDX_NX: u32 = 1 << 20;

const EFI_LOADER_CODE: u32 = 1;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_RUNTIME_SERVICES_CODE: u32 = 5;

#[derive(Clone, Copy, Debug)]
pub enum PagingError {
    ArenaExhausted,
    AddressOverflow,
    PhysicalAddressTooWide,
    MappingConflict,
    MissingGuardMapping,
}

pub struct HostPageTables {
    root: u64,
    mapped_4k_pages: u64,
    nx_enabled: bool,
}

impl HostPageTables {
    pub fn build(
        memory_map: MemoryMap,
        arena: &mut BootArena,
        guard_pages: &[u64],
    ) -> Result<Self, PagingError> {
        let nx_enabled = enable_nx();
        let root = allocate_table(arena)?;
        let mut builder = Builder {
            root,
            arena,
            mapped_4k_pages: 0,
            nx_enabled,
        };

        for descriptor in memory_map.descriptors() {
            if descriptor.number_of_pages == 0 {
                continue;
            }
            let length = descriptor
                .number_of_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(PagingError::AddressOverflow)?;
            let end = descriptor
                .physical_start
                .checked_add(length)
                .ok_or(PagingError::AddressOverflow)?;
            if end > (1u64 << 52) {
                return Err(PagingError::PhysicalAddressTooWide);
            }
            let executable = matches!(
                descriptor.memory_type,
                EFI_LOADER_CODE | EFI_BOOT_SERVICES_CODE | EFI_RUNTIME_SERVICES_CODE
            );
            builder.map_identity(descriptor.physical_start, end, executable)?;
        }

        for &guard in guard_pages {
            builder.unmap_4k(guard)?;
        }

        Ok(Self {
            root,
            mapped_4k_pages: builder.mapped_4k_pages,
            nx_enabled,
        })
    }
    pub unsafe fn activate(&self) {
        let cr0 = read_cr0() | CR0_WRITE_PROTECT;
        unsafe {
            write_cr0(cr0);
            write_cr3(self.root);
        }
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    pub fn mapped_4k_pages(&self) -> u64 {
        self.mapped_4k_pages
    }

    pub fn nx_enabled(&self) -> bool {
        self.nx_enabled
    }
}

struct Builder<'a> {
    root: u64,
    arena: &'a mut BootArena,
    mapped_4k_pages: u64,
    nx_enabled: bool,
}

impl Builder<'_> {
    fn map_identity(
        &mut self,
        mut address: u64,
        end: u64,
        executable: bool,
    ) -> Result<(), PagingError> {
        address = address.max(PAGE_SIZE);
        while address < end {
            let remaining = end - address;
            if address & (LARGE_PAGE_SIZE - 1) == 0 && remaining >= LARGE_PAGE_SIZE {
                self.map_2m(address, executable)?;
                address += LARGE_PAGE_SIZE;
                self.mapped_4k_pages += LARGE_PAGE_SIZE / PAGE_SIZE;
            } else {
                self.map_4k(address, executable)?;
                address += PAGE_SIZE;
                self.mapped_4k_pages += 1;
            }
        }
        Ok(())
    }

    fn map_4k(&mut self, address: u64, executable: bool) -> Result<(), PagingError> {
        let pml4 = self.root;
        let pdpt = self.next_table(pml4, index(address, 39))?;
        let pd = self.next_table(pdpt, index(address, 30))?;
        let pt = self.next_table(pd, index(address, 21))?;
        let pte = entry_pointer(pt, index(address, 12));
        // SAFETY: page-table pages are exclusive and identity-mapped while built.
        if unsafe { pte.read() } & PRESENT != 0 {
            return Err(PagingError::MappingConflict);
        }
        // SAFETY: PTE points inside the allocated page-table page.
        unsafe { pte.write(address | self.leaf_flags(executable)) };
        Ok(())
    }

    fn map_2m(&mut self, address: u64, executable: bool) -> Result<(), PagingError> {
        let pml4 = self.root;
        let pdpt = self.next_table(pml4, index(address, 39))?;
        let pd = self.next_table(pdpt, index(address, 30))?;
        let pde = entry_pointer(pd, index(address, 21));
        if unsafe { pde.read() } & PRESENT != 0 {
            return Err(PagingError::MappingConflict);
        }
        unsafe { pde.write(address | self.leaf_flags(executable) | HUGE) };
        Ok(())
    }

    fn next_table(&mut self, table: u64, entry_index: usize) -> Result<u64, PagingError> {
        let entry = entry_pointer(table, entry_index);
        let value = unsafe { entry.read() };
        if value & PRESENT != 0 {
            if value & HUGE != 0 {
                return Err(PagingError::MappingConflict);
            }
            return Ok(value & ADDRESS_MASK);
        }
        let next = allocate_table(self.arena)?;
        unsafe { entry.write(next | PRESENT | WRITABLE) };
        Ok(next)
    }

    fn unmap_4k(&mut self, address: u64) -> Result<(), PagingError> {
        let pdpt = self.existing_table(self.root, index(address, 39))?;
        let pd = self.existing_table(pdpt, index(address, 30))?;
        let pde = entry_pointer(pd, index(address, 21));
        let pde_value = unsafe { pde.read() };
        let pt = if pde_value & PRESENT == 0 {
            return Err(PagingError::MissingGuardMapping);
        } else if pde_value & HUGE != 0 {
            let new_pt = allocate_table(self.arena)?;
            let base = pde_value & ADDRESS_MASK;
            let flags = pde_value & !ADDRESS_MASK & !HUGE;
            for offset in 0..ENTRY_COUNT {
                let page = base + (offset as u64 * PAGE_SIZE);
                unsafe { entry_pointer(new_pt, offset).write(page | flags) };
            }
            unsafe { pde.write(new_pt | PRESENT | WRITABLE) };
            new_pt
        } else {
            pde_value & ADDRESS_MASK
        };
        let pte = entry_pointer(pt, index(address, 12));
        if unsafe { pte.read() } & PRESENT == 0 {
            return Err(PagingError::MissingGuardMapping);
        }
        unsafe { pte.write(0) };
        self.mapped_4k_pages -= 1;
        Ok(())
    }

    fn existing_table(&self, table: u64, entry_index: usize) -> Result<u64, PagingError> {
        let value = unsafe { entry_pointer(table, entry_index).read() };
        if value & PRESENT == 0 || value & HUGE != 0 {
            return Err(PagingError::MissingGuardMapping);
        }
        Ok(value & ADDRESS_MASK)
    }

    fn leaf_flags(&self, executable: bool) -> u64 {
        let nx = if self.nx_enabled && !executable {
            NO_EXECUTE
        } else {
            0
        };
        PRESENT | WRITABLE | nx
    }
}

fn index(address: u64, shift: u32) -> usize {
    ((address >> shift) & 0x1ff) as usize
}

fn entry_pointer(table: u64, index: usize) -> *mut u64 {
    debug_assert!(index < ENTRY_COUNT);
    (table as *mut u64).wrapping_add(index)
}

fn allocate_table(arena: &mut BootArena) -> Result<u64, PagingError> {
    let page = arena
        .allocate_pages(1)
        .ok_or(PagingError::ArenaExhausted)?;
    unsafe { ptr::write_bytes(page.as_ptr(), 0, PAGE_SIZE as usize) };
    Ok(page.as_ptr() as u64)
}

fn enable_nx() -> bool {
    if cpuid(CPUID_EXTENDED_MAX, 0).eax < CPUID_EXTENDED_FEATURES
        || cpuid(CPUID_EXTENDED_FEATURES, 0).edx & CPUID_EDX_NX == 0
    {
        return false;
    }
    let efer = unsafe { rdmsr(IA32_EFER) };
    unsafe { wrmsr(IA32_EFER, efer | EFER_NXE) };
    true
}

