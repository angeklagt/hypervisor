use core::ptr;

use crate::uefi::{EfiMemoryDescriptor, Handoff};

const PAGE_SIZE: u64 = 4096;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const MAX_FREE_RANGES: usize = 256;

#[derive(Clone, Copy, Debug)]
pub enum MemoryError {
    NullMap,
    InvalidStride,
    InvalidLength,
    AddressOverflow,
    TooManyRanges,
}

#[derive(Clone, Copy)]
pub struct MemoryMap {
    base: *const u8,
    size: usize,
    stride: usize,
}

impl MemoryMap {
    pub unsafe fn from_handoff(handoff: &Handoff) -> Result<Self, MemoryError> {
        if handoff.memory_map.is_null() {
            return Err(MemoryError::NullMap);
        }
        if handoff.descriptor_size < core::mem::size_of::<EfiMemoryDescriptor>() {
            return Err(MemoryError::InvalidStride);
        }
        if handoff.memory_map_size == 0
            || handoff.memory_map_size % handoff.descriptor_size != 0
        {
            return Err(MemoryError::InvalidLength);
        }
        Ok(Self {
            base: handoff.memory_map,
            size: handoff.memory_map_size,
            stride: handoff.descriptor_size,
        })
    }

    pub fn descriptors(self) -> MemoryMapIter {
        MemoryMapIter {
            map: self,
            offset: 0,
        }
    }

    pub fn descriptor_count(self) -> usize {
        self.size / self.stride
    }
}

pub struct MemoryMapIter {
    map: MemoryMap,
    offset: usize,
}

impl Iterator for MemoryMapIter {
    type Item = EfiMemoryDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.map.size {
            return None;
        }
        let address = unsafe { self.map.base.add(self.offset) };
        self.offset += self.map.stride;
        Some(unsafe { ptr::read_unaligned(address.cast::<EfiMemoryDescriptor>()) })
    }
}

#[derive(Clone, Copy)]
struct FrameRange {
    start: u64,
    end: u64,
}

const EMPTY_RANGE: FrameRange = FrameRange { start: 0, end: 0 };

pub struct FrameAllocator {
    ranges: [FrameRange; MAX_FREE_RANGES],
    range_count: usize,
    total_pages: u64,
}

impl FrameAllocator {
    pub fn from_memory_map(map: MemoryMap) -> Result<Self, MemoryError> {
        let mut allocator = Self {
            ranges: [EMPTY_RANGE; MAX_FREE_RANGES],
            range_count: 0,
            total_pages: 0,
        };

        for descriptor in map.descriptors() {
            if descriptor.memory_type != EFI_CONVENTIONAL_MEMORY
                || descriptor.number_of_pages == 0
            {
                continue;
            }
            let bytes = descriptor
                .number_of_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(MemoryError::AddressOverflow)?;
            let end = descriptor
                .physical_start
                .checked_add(bytes)
                .ok_or(MemoryError::AddressOverflow)?;
            allocator.push(FrameRange {
                start: descriptor.physical_start,
                end,
            })?;
        }

        allocator.sort_and_merge();
        allocator.total_pages = allocator.ranges[..allocator.range_count]
            .iter()
            .map(|range| (range.end - range.start) / PAGE_SIZE)
            .sum();
        Ok(allocator)
    }

    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    pub fn range_count(&self) -> usize {
        self.range_count
    }

    pub fn allocate_pages(&mut self, page_count: usize) -> Option<u64> {
        let bytes = (page_count as u64).checked_mul(PAGE_SIZE)?;
        if bytes == 0 {
            return None;
        }
        for index in (0..self.range_count).rev() {
            let range = &mut self.ranges[index];
            if range.end - range.start < bytes {
                continue;
            }
            range.end -= bytes;
            self.total_pages -= page_count as u64;
            return Some(range.end);
        }
        None
    }

    fn push(&mut self, range: FrameRange) -> Result<(), MemoryError> {
        if range.start & (PAGE_SIZE - 1) != 0 || range.end & (PAGE_SIZE - 1) != 0 {
            return Err(MemoryError::InvalidLength);
        }
        if self.range_count == MAX_FREE_RANGES {
            return Err(MemoryError::TooManyRanges);
        }
        self.ranges[self.range_count] = range;
        self.range_count += 1;
        Ok(())
    }

    fn sort_and_merge(&mut self) {
        for index in 1..self.range_count {
            let value = self.ranges[index];
            let mut cursor = index;
            while cursor > 0 && self.ranges[cursor - 1].start > value.start {
                self.ranges[cursor] = self.ranges[cursor - 1];
                cursor -= 1;
            }
            self.ranges[cursor] = value;
        }

        let mut output = 0usize;
        for index in 0..self.range_count {
            let current = self.ranges[index];
            if output != 0 && current.start <= self.ranges[output - 1].end {
                self.ranges[output - 1].end =
                    self.ranges[output - 1].end.max(current.end);
            } else {
                self.ranges[output] = current;
                output += 1;
            }
        }
        self.range_count = output;
    }
}

