
///
/// Windows NT header or PE header
/// Win32 API structure, which binds special
/// parts "tables" 
/// 
/// `nt_signature` field not depends on
/// architecture specific. 
/// (means: not depends on BYTE/WORD ordering or endiannes)
/// 
#[repr(C)]
pub struct ImageNTHeader32 {
    pub nt_magic: u32,
    pub nt_file_header: ImageFileHeader,
    pub nt_optional_header: ImageOptionalHeader32
}

#[repr(C)]
pub struct ImageNTHeader64 {
    pub nt_magic: u32,
    pub nt_file_header: ImageFileHeader,
    pub nt_optional_header: ImageOptionalHeader64
}
///
/// Important part for each Portable Executable file
/// names like "COFF header" or "file header".
/// 
#[repr(C)]
pub struct ImageFileHeader {
    pub e_machine: u16,
    pub e_number_of_sections: u16,
    pub e_time_stamp: u32,
    pub e_number_of_symbols: u16,
    pub e_size_of_optional_header: u16,
    pub e_characteristics: u16
}
///
/// Optional part of Windows NT header (see IMAGE_NT_HEADER in WinAPI)
/// 
/// EFI drivers, segmented like Portable Executable doesn't have
/// this structure. That's why it names "Optional"
/// Other drivers/dlls/executables must have this part.
/// 
#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub e_magic: u16, // PE32/+ sign
    pub e_linker_major: u8,
    pub e_linker_minor: u8,
    pub e_size_of_code: u32,
    pub e_size_of_init: u32,
    pub e_size_of_deinit: u32,
    pub e_address_entry_point: u32,
    pub e_base_of_code: u32,
    pub e_base_of_data: u32,
    pub e_image_base: u32,
    pub e_section_align: u32,
    pub e_file_align: u32,
    pub e_os_major: u16,
    pub e_os_minor: u16,
    pub e_image_major: u16,
    pub e_image_minor: u16,
    pub e_subsys_major: u16,
    pub e_subsys_minor: u16,
    pub e_win32: u32,
    pub e_size_of_image: u32,
    pub e_size_of_headers: u32,
    pub e_checksum: u32,
    pub e_subsys: u16,
    pub e_dll_characteristics: u16,
    
    pub e_size_of_stack_reserve: u32,
    pub e_size_of_stack_commit: u32,
    pub e_size_of_heap_reserve: u32,
    pub e_size_of_heap_commit: u32,

    pub e_loader_flags: u32,
    pub e_number_of_directories: u32,
    pub e_directories: [ImageDirectory; DIRECTORIES_COUNT] // always 16 in Optional header part
}
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub e_magic: u16, // PE32/+ sign
    pub e_linker_major: u8,
    pub e_linker_minor: u8,
    pub e_size_of_code: u32,
    pub e_size_of_init: u32,
    pub e_size_of_deinit: u32,
    pub e_address_entry_point: u32,
    pub e_base_of_code: u32,
    pub e_base_of_data: u32,
    pub e_image_base: u32,
    pub e_section_align: u32,
    pub e_file_align: u32,
    pub e_os_major: u16,
    pub e_os_minor: u16,
    pub e_image_major: u16,
    pub e_image_minor: u16,
    pub e_subsys_major: u16,
    pub e_subsys_minor: u16,
    pub e_win32: u32,
    pub e_size_of_image: u32,
    pub e_size_of_headers: u32,
    pub e_checksum: u32,
    pub e_subsys: u16,
    pub e_dll_characteristics: u16,
    
    pub e_size_of_stack_reserve: u64,
    pub e_size_of_stack_commit: u64,
    pub e_size_of_heap_reserve: u64,
    pub e_size_of_heap_commit: u64,

    pub e_loader_flags: u32,
    pub e_number_of_directories: u32,
    pub e_directories: [ImageDirectory; DIRECTORIES_COUNT] // always 16 in Optional header part
}
///
/// Logical parts/segments of PE image
/// which stores in file sections 
/// 
#[repr(C)]
pub struct ImageDirectory {
    d_virtual_address: u32,
    d_size: u32
}

pub const DIRECTORIES_COUNT: usize = 0x10; 
pub const DIRECTORY_EXPORTS: u8 = 0x00;
pub const DIRECTORY_IMPORT_STATIC: u8 = 0x01;
pub const DIRECTORY_RESOURCE: u8 = 0x02;
pub const DIRECTORY_EXCEPTION: u8 = 0x03; // Windows Structured Exceptions chain
pub const DIRECTORY_SECURITY: u8 = 0x04;
pub const DIRECTORY_RELOCATIONS: u8 = 0x05;
pub const DIRECTORY_DEBUG: u8 = 0x06;
pub const DIRECTORY_ARCHITECTURE: u8 = 0x07; // modern translation. Arch specifix;
pub const DIRECTORY_GLOBAL_POINTER: u8 = 0x08;
pub const DIRECTORY_THREAD_STORAGE: u8 = 0x09;
pub const DIRECTORY_LOAD_CONFIG: u8 = 0x0A;
pub const DIRECTORY_IMPORT_BOUND: u8 = 0x0B;
pub const DIRECTORY_IMPORT_ADDRESS_TABLE: u8 = 0x0C;
pub const DIRECTORY_IMPORT_DELAYED: u8 = 0x0D;
pub const DIRECTORY_COM_DESCRIPTOR: u8 = 0x0E;

///
/// Sections Table header
/// 
/// Section is a physical partition of file
/// which can has Directories.
/// 
/// In example, section .text (or "code section")
/// has ImportsDirectory and ExportsDirectory
/// but implicit ".edata" or ".idata" are missing.
/// 
/// All sections has 8 bytes long CSTR name.
/// ['\0', '\0', '\0', 'a', 't', 'a', 'd', '.'] -> ".data"
/// 
#[repr(C)]
pub struct ImageSectionHeader {
    pub s_name: [u8; 8],
    pub s_misc: ImageSectionMisc,
    pub s_virtual_address: u32,
    pub s_size_of_raw_data: u32,
    pub s_pointer_to_raw_data: u32,
    pub s_pointer_to_relocations: u32,
    pub s_pointer_to_linenumbers: u32,
    pub s_number_of_relocations: u16,
    pub s_number_of_linenumbers: u16,
    pub s_characteristics: u32
}
#[repr(C)]
pub union ImageSectionMisc {
    pub m_physical_address: u32,
    pub m_virtual_size: u32
}
#[repr(C)]
pub union DummyUnionName {
    pub n_characteristics: u32,
    pub n_original_first_thunk: u32 // <-- procedures array
}
#[repr(C)]
pub struct ImageImportDescriptor {
    pub i_dummy_union_name: DummyUnionName,
    pub i_time_stamp: u32,
    pub i_forwarder_chain: u32,
    pub i_name_rva: u32,    // <-- DLL name rva.
    pub i_first_thunk: u32  // <-- position in IAT
}
#[repr(C)]
pub struct ImageImportByName {
    pub i_hint: u16,
    pub i_name: [u8; 1]
}