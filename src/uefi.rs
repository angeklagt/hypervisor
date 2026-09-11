use core::mem::{self, MaybeUninit};
use core::ptr::{self, NonNull};

pub type EfiHandle = *mut core::ffi::c_void;
pub type EfiStatus = usize;
type EfiPhysicalAddress = u64;

const EFI_SUCCESS: EfiStatus = 0;
const EFI_ERROR_BIT: EfiStatus = 1usize << (usize::BITS - 1);
const EFI_INVALID_PARAMETER: EfiStatus = EFI_ERROR_BIT | 2;
const EFI_BUFFER_TOO_SMALL: EfiStatus = EFI_ERROR_BIT | 5;
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x5652_4553_544f_4f42;

const ALLOCATE_ANY_PAGES: u32 = 0;
const EFI_LOADER_DATA: u32 = 2;
const PAGE_SIZE: usize = 4096;
const STACK_PAGES: usize = 17; // One guard page plus sixteen usable pages.
const BOOTSTRAP_ARENA_PAGES: usize = 1024;
const MEMORY_MAP_CAPACITY: usize = 256 * 1024;
const EXIT_RETRIES: usize = 8;

#[repr(C)]
pub struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
pub struct EfiSystemTable {
    header: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    _padding: u32,
    console_in_handle: EfiHandle,
    con_in: *mut core::ffi::c_void,
    console_out_handle: EfiHandle,
    con_out: *mut core::ffi::c_void,
    standard_error_handle: EfiHandle,
    std_err: *mut core::ffi::c_void,
    runtime_services: *mut core::ffi::c_void,
    boot_services: *mut EfiBootServices,
    number_of_table_entries: usize,
    configuration_table: *mut core::ffi::c_void,
}

type AllocatePages = unsafe extern "efiapi" fn(
    allocation_type: u32,
    memory_type: u32,
    pages: usize,
    memory: *mut EfiPhysicalAddress,
) -> EfiStatus;
type FreePages = unsafe extern "efiapi" fn(
    memory: EfiPhysicalAddress,
    pages: usize,
) -> EfiStatus;
type GetMemoryMap = unsafe extern "efiapi" fn(
    memory_map_size: *mut usize,
    memory_map: *mut EfiMemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> EfiStatus;
type ExitBootServices = unsafe extern "efiapi" fn(
    image_handle: EfiHandle,
    map_key: usize,
) -> EfiStatus;

#[repr(C)]
pub struct EfiBootServices {
    header: EfiTableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: AllocatePages,
    free_pages: FreePages,
    get_memory_map: GetMemoryMap,
    allocate_pool: usize,
    free_pool: usize,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: usize,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: usize,
    start_image: usize,
    exit: usize,
    unload_image: usize,
    exit_boot_services: ExitBootServices,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub _padding: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attributes: u64,
}

#[repr(C)]
pub struct Handoff {
    pub memory_map: *const u8,
    pub memory_map_size: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
    pub _padding: u32,
    pub stack_guard: u64,
    pub stack_base: u64,
    pub stack_top: u64,
    pub vmxon_region: u64,
    pub bootstrap_arena_base: u64,
    pub bootstrap_arena_size: u64,
}

pub struct Prepared {
    stack_guard: u64,
    stack_base: u64,
    stack_top: u64,
    vmxon_region: u64,
    bootstrap_arena_base: u64,
    handoff: NonNull<Handoff>,
}

pub struct Loader {
    image_handle: EfiHandle,
    boot_services: NonNull<EfiBootServices>,
}

static mut MEMORY_MAP: [u8; MEMORY_MAP_CAPACITY] = [0; MEMORY_MAP_CAPACITY];

const _: () = assert!(mem::size_of::<EfiTableHeader>() == 24);
const _: () = assert!(mem::offset_of!(EfiSystemTable, boot_services) == 96);
const _: () = assert!(mem::offset_of!(EfiBootServices, allocate_pages) == 40);
const _: () = assert!(mem::offset_of!(EfiBootServices, get_memory_map) == 56);
const _: () = assert!(mem::offset_of!(EfiBootServices, exit_boot_services) == 232);

impl Loader {
    pub unsafe fn new(
        image_handle: EfiHandle,
        system_table: *mut EfiSystemTable,
    ) -> Result<Self, EfiStatus> {
        let system_table = NonNull::new(system_table).ok_or(EFI_INVALID_PARAMETER)?;
        let system_table_ref = unsafe { system_table.as_ref() };
        if system_table_ref.header.signature != EFI_SYSTEM_TABLE_SIGNATURE
            || system_table_ref.header.header_size < mem::size_of::<EfiSystemTable>() as u32
        {
            return Err(EFI_INVALID_PARAMETER);
        }
        let boot_services =
            NonNull::new(system_table_ref.boot_services).ok_or(EFI_INVALID_PARAMETER)?;
        let boot_services_ref = unsafe { boot_services.as_ref() };
        if boot_services_ref.header.signature != EFI_BOOT_SERVICES_SIGNATURE
            || boot_services_ref.header.header_size
                < (mem::offset_of!(EfiBootServices, exit_boot_services)
                    + mem::size_of::<ExitBootServices>()) as u32
        {
            return Err(EFI_INVALID_PARAMETER);
        }
        Ok(Self { image_handle, boot_services })
    }

    pub fn prepare(&mut self) -> Result<Prepared, EfiStatus> {
        let stack_base = self.allocate_pages(STACK_PAGES)?;
        let vmxon_region = match self.allocate_pages(1) {
            Ok(address) => address,
            Err(status) => {
                self.free_pages(stack_base, STACK_PAGES);
                return Err(status);
            }
        };
        let handoff_page = match self.allocate_pages(1) {
            Ok(address) => address,
            Err(status) => {
                self.free_pages(vmxon_region, 1);
                self.free_pages(stack_base, STACK_PAGES);
                return Err(status);
            }
        };
        let bootstrap_arena_base = match self.allocate_pages(BOOTSTRAP_ARENA_PAGES) {
            Ok(address) => address,
            Err(status) => {
                self.free_pages(handoff_page, 1);
                self.free_pages(vmxon_region, 1);
                self.free_pages(stack_base, STACK_PAGES);
                return Err(status);
            }
        };

        unsafe {
            ptr::write_bytes(stack_base as *mut u8, 0, STACK_PAGES * PAGE_SIZE);
            ptr::write_bytes(vmxon_region as *mut u8, 0, PAGE_SIZE);
            ptr::write_bytes(handoff_page as *mut u8, 0, PAGE_SIZE);
            ptr::write_bytes(
                bootstrap_arena_base as *mut u8,
                0,
                BOOTSTRAP_ARENA_PAGES * PAGE_SIZE,
            );
        }
        let handoff = NonNull::new(handoff_page as *mut Handoff)
            .ok_or(EFI_INVALID_PARAMETER)?;

        Ok(Prepared {
            stack_guard: stack_base,
            stack_base: stack_base + PAGE_SIZE as u64,
            stack_top: stack_base + (STACK_PAGES * PAGE_SIZE) as u64,
            vmxon_region,
            bootstrap_arena_base,
            handoff,
        })
    }

    pub fn exit_boot_services(
        &mut self,
        prepared: Prepared,
    ) -> Result<*const Handoff, EfiStatus> {
        for _ in 0..EXIT_RETRIES {
            let mut map_size = MEMORY_MAP_CAPACITY;
            let mut map_key = 0usize;
            let mut descriptor_size = 0usize;
            let mut descriptor_version = 0u32;
            let status = unsafe {
                (self.boot_services.as_ref().get_memory_map)(
                    &mut map_size,
                    ptr::addr_of_mut!(MEMORY_MAP).cast::<EfiMemoryDescriptor>(),
                    &mut map_key,
                    &mut descriptor_size,
                    &mut descriptor_version,
                )
            };
            if status == EFI_BUFFER_TOO_SMALL {
                return Err(status); 
            }
            if status != EFI_SUCCESS {
                return Err(status);
            }
            if descriptor_size < mem::size_of::<EfiMemoryDescriptor>() {
                return Err(EFI_INVALID_PARAMETER);
            }
            if map_size % descriptor_size != 0 {
                return Err(EFI_INVALID_PARAMETER);
            }

            let value = Handoff {
                memory_map: ptr::addr_of!(MEMORY_MAP).cast::<u8>(),
                memory_map_size: map_size,
                descriptor_size,
                descriptor_version,
                _padding: 0,
                stack_guard: prepared.stack_guard,
                stack_base: prepared.stack_base,
                stack_top: prepared.stack_top,
                vmxon_region: prepared.vmxon_region,
                bootstrap_arena_base: prepared.bootstrap_arena_base,
                bootstrap_arena_size: (BOOTSTRAP_ARENA_PAGES * PAGE_SIZE) as u64,
            };
            unsafe { prepared.handoff.as_ptr().write(value) };

            let status = unsafe {
                (self.boot_services.as_ref().exit_boot_services)(self.image_handle, map_key)
            };
            if status == EFI_SUCCESS {
                return Ok(prepared.handoff.as_ptr());
            }
            if status != EFI_INVALID_PARAMETER {
                return Err(status);
            }
        }
        Err(EFI_INVALID_PARAMETER)
    }

    fn allocate_pages(&mut self, page_count: usize) -> Result<u64, EfiStatus> {
        let mut address = MaybeUninit::<EfiPhysicalAddress>::new(0);
        let status = unsafe {
            (self.boot_services.as_ref().allocate_pages)(
                ALLOCATE_ANY_PAGES,
                EFI_LOADER_DATA,
                page_count,
                address.as_mut_ptr(),
            )
        };
        if status != EFI_SUCCESS {
            return Err(status);
        }
        Ok(unsafe { address.assume_init() })
    }

    fn free_pages(&mut self, address: u64, page_count: usize) {
        unsafe {
            let _ = (self.boot_services.as_ref().free_pages)(address, page_count);
        }
    }
}
