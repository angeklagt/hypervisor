use core::ptr::NonNull;

const PAGE_SIZE: u64 = 4096;

pub struct BootArena {
    next: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum BootAllocError {
    Empty,
    Misaligned,
    Overflow,
}

impl BootArena {
    pub unsafe fn new(base: u64, length: u64) -> Result<Self, BootAllocError> {
        if length == 0 {
            return Err(BootAllocError::Empty);
        }
        if base & (PAGE_SIZE - 1) != 0 || length & (PAGE_SIZE - 1) != 0 {
            return Err(BootAllocError::Misaligned);
        }
        let end = base.checked_add(length).ok_or(BootAllocError::Overflow)?;
        Ok(Self { next: base, end })
    }

    pub fn allocate_pages(&mut self, page_count: usize) -> Option<NonNull<u8>> {
        let bytes = (page_count as u64).checked_mul(PAGE_SIZE)?;
        self.allocate(bytes as usize, PAGE_SIZE as usize)
    }

    pub fn allocate(&mut self, size: usize, alignment: usize) -> Option<NonNull<u8>> {
        if size == 0 || !alignment.is_power_of_two() {
            return None;
        }
        let mask = (alignment as u64).checked_sub(1)?;
        let start = self.next.checked_add(mask)? & !mask;
        let next = start.checked_add(size as u64)?;
        if next > self.end {
            return None;
        }
        self.next = next;
        NonNull::new(start as *mut u8)
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.end - self.next
    }
}

