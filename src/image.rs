use crate::headers::{dos::{self, ImageDOSHeader}, windows::{self, *}};
use std::{io, ptr};
use std::rc::Rc;
// avoid the C/++ style => use pattern matching
///
/// Represents available types of IMAGE_NT_HEADER
/// for required PE image.
///
//  
// https://doc.rust-lang.org/book/ch10-02-traits.html#returning-types-that-implement-traits
// https://doc.rust-lang.org/book/ch06-02-match.html
pub enum NTHeaderType {
    Machine32Bit(ImageNTHeader32),
    Machine64Bit(ImageNTHeader64),
    // MachineROM(ImageROMHeader),
}
///
/// Implement the general characteristics
/// contained in different data-structures
/// 
impl NTHeaderType {
    pub fn get_number_of_sections(&self) -> u16 {
        match self {
            Self::Machine32Bit(h) => h.nt_file_header.e_number_of_sections,
            Self::Machine64Bit(h) => h.nt_file_header.e_number_of_sections
        }
    }
    pub fn get_image_size(&self) -> u32 {
        match self {
            Self::Machine32Bit(h) => h.nt_optional_header.e_size_of_image,
            Self::Machine64Bit(h) => h.nt_optional_header.e_size_of_image,
            
        }
    }
    pub fn get_image_base(&self) -> u32 {
        match self {
            Self::Machine32Bit(h) => h.nt_optional_header.e_image_base,
            Self::Machine64Bit(h) => h.nt_optional_header.e_image_base
        }
    }
    pub fn get_size_of_headers(&self) -> u32 {
        match self {
            Self::Machine32Bit(h) => h.nt_optional_header.e_size_of_headers,
            Self::Machine64Bit(h) => h.nt_optional_header.e_size_of_headers
        }
    }
    pub fn get_import_static_directory(&self) -> ImageDirectory {
        match self {
            Self::Machine32Bit(h) => h.nt_optional_header.e_import_static_directory,
            Self::Machine64Bit(h) => h.nt_optional_header.e_import_static_directory
        }
    }
    pub fn get_optional_header_size(&self) -> u16 {
        match self {
            Self::Machine32Bit(h) => h.nt_file_header.e_size_of_optional_header,
            Self::Machine64Bit(h) => h.nt_file_header.e_size_of_optional_header
        }
    }
}
///
/// Fills and defines type of PE image
/// /will image be like 64-bit linked or 32-nit /
/// 
/// Actually matches header type by `e_magic` field
/// PE32/+ image field set in IMAGE_OPTIONAL_HEADER 
/// 
pub fn try_get_nt_header(image: &[u8]) -> io::Result<NTHeaderType> {
    let mz_header = bytemuck::from_bytes::<ImageDOSHeader>(image
        .get(..std::mem::size_of::<ImageDOSHeader>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid DOS header size"))?
    );

    if mz_header.e_magic != dos::IMAGE_DOS_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DOS part is incompat"));
    }

    let nt_header_offset = mz_header.e_lfanew as usize;
    let nt_magic_bytes = image
        .get(nt_header_offset..nt_header_offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "NT header out of bounds"))?;


    if nt_magic_bytes != b"PE\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PE image signature not compatible"
        ));
    }
    let optional_magic_offset = nt_header_offset + windows::NT_OPTIONAL_HEADER_OFFSET;
    let optional_magic_bytes = image.get(optional_magic_offset..optional_magic_offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Optional header out of bounds"))?;
    
    // PE32/+ sign matching
    match u16::from_le_bytes(optional_magic_bytes.try_into().unwrap()) {
        windows::IMAGE_NT_32_SIGNATURE => {
            let header = *bytemuck::from_bytes::<ImageNTHeader32>(image
                    .get(optional_magic_offset..std::mem::size_of::<ImageNTHeader32>()) 
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PE32 header incomplete"))?
            );
            Ok(NTHeaderType::Machine32Bit(header))
        },
        windows::IMAGE_NT_64_SIGNATURE => {
            let header = *bytemuck::from_bytes(image
                .get(optional_magic_offset..std::mem::size_of::<ImageNTHeader64>())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PE32+ header incomplete"))?
            );
            Ok(NTHeaderType::Machine64Bit(header))
        }
        magic => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Signature extra mismatch {:X}", magic)))
    }
}
///
/// WinPackage firstly tries to find special .packed
/// section if current image by filename was compressed.
/// 
/// Section `.packed` contains special keyword 
/// which in some ways you may imagine it like 
/// password by archive
/// 
/// This is the most simple logic of packagers
/// and this program represents my little experience
/// 
/// For real: UPX has own header (in example) which points
/// on specific structures located in file.
/// 
pub fn try_get_packed_section(
    image: &[u8], 
    nt_header: &NTHeaderType) -> io::Result<ImageSectionHeader> {
    
    let sections_offset = 
        nt_header as *const _ as usize - image.as_ptr() as usize
        + std::mem::size_of::<ImageNTHeader32>();
    
    // headers_scope = N * section_head_len
    let sections_count = nt_header.get_number_of_sections() as usize;
    let sections_bytes = image
        .get(sections_offset..(sections_offset + (sections_count * std::mem::size_of::<ImageSectionHeader>())))
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unable to find sections scope"
        ))?;
    
    let sections_slice = bytemuck::cast_slice::<u8, ImageSectionHeader>(sections_bytes);

    let no_sections_err: io::Error = io::Error::new(
        io::ErrorKind::NotFound,
        "Unable to find PE sections"
    );
    let result = *sections_slice
            .iter() // cast Iterator<T> instance
            .find(|h| h.s_name.starts_with(b".packed"))
            .ok_or(no_sections_err)?;

    return Ok(result);
}
///
/// Tries to decompress and decrypt PE image.
/// returns _optional_ type.
/// 
/// Requirements:
///  - .packed section
///  - correct sizes
///  - correct XOR key (raw bytes from ASCII string.. NOT CStr)
/// 
pub fn try_decrypt_image(packed_section: ImageSectionHeader, image_base: &[u8], mask: &[u8]) -> io::Result<Vec<u8>>{
    let start = packed_section.s_virtual_address as usize;
    let end = start + packed_section.s_size_of_raw_data as usize;

    let section_data = image_base
        .get(start..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Packed section out of bounds"))?;

    let unpacked_size = section_data
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid unpacked size"))? as usize;
    
    // warning.
    let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(image_base) // <-- compressed_data
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    match decompressed.len() != unpacked_size {
        true => {
            return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Processed sizes are different\r\n\texpected: {}\r\n\tgot{}",
                        unpacked_size,
                        decompressed.len()
                    )
                ));
        }
        false => (),
    }

    // XOR mask
    let decrypted = decompressed
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % mask.len()].saturating_add(1))
        .collect();

    return Ok(decrypted);

}
///
/// Returns section headers slice for un/packing 
/// procedure or unpacking procedure Error.
/// 
pub fn try_get_sections_slice(
    image: &[u8],
    nt_offset: usize,
    num_sections: u16,
) -> io::Result<&[ImageSectionHeader]> {
    let sections_offset = nt_offset + std::mem::size_of::<u32>() + // nt_magic
        std::mem::size_of::<ImageFileHeader>();
    
    let sections_size = num_sections as usize * std::mem::size_of::<ImageSectionHeader>();
    
    let sections_bytes = image.get(sections_offset..sections_offset + sections_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: sections table out of bounds"))?;
    
    Ok(bytemuck::cast_slice(sections_bytes))
}
///
/// Prepare, Call Win32 API for PE32/+ image
/// 
/// Tries allocate virtual memory for PE image
/// and load it by module descriptor (see HMODULE from Windows API)
/// 
/// Marked unsafe because contains OS ABI calls.
/// /TODO: rewrite unsafe scope with [safe_ffi] crate calls/
/// 
unsafe fn try_load_decompressed_image(image: &[u8]) -> io::Result<*mut u8> {
    let dos_header = bytemuck::from_bytes::<ImageDOSHeader>(image
            .get(0..std::mem::size_of::<ImageDOSHeader>())
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Unable to allocate DOS header space"))?
    );
    let nt_header = try_get_nt_header(image)?;
    let image_size = nt_header.get_image_size() as usize;

    // LPVOID for IA32(e) based machines same with next C-declared expression: 
    // typedef void *LPVOID;

    // alloc virtual memory
    let lp_image_base = unsafe { // this is a LPVOID interpretation
        winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(),
            image_size,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        )
    };

    if lp_image_base.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("VirtualAlloc failed: {}", unsafe { winapi::um::errhandlingapi::GetLastError() }),
        ));
    }

    // how to alloc memory more safe
    let image_base_slice = unsafe {
        std::slice::from_raw_parts_mut(lp_image_base as *mut u8, image_size)
    }; 
    let image_base_ptr = lp_image_base as *mut u8;

    //
    // Now procedure starts to copy necessary PE image parts.
    // 
    
    let header_size = nt_header.get_size_of_headers() as usize;
    image_base_slice[..header_size].copy_from_slice(
        image
            .get(..header_size)
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "stopped: invalid header size"))?,
    );

    let sections = image
        .get(std::mem::size_of::<ImageDOSHeader>() + std::mem::size_of::<ImageNTHeader32>()..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No sections data"));

    let sections = match try_get_sections_slice(image, (dos_header.e_lfanew as usize), nt_header.get_number_of_sections()) { // what is actually nt_offset means??
        Ok(s) => s,
        Err(e) => return Err(e) // TODO: hide all procedure signs.
    };

    for section in sections {
        if section.s_size_of_raw_data > 0 {
            let src_start = section.s_pointer_to_raw_data as usize;
            let src_end = src_start + section.s_size_of_raw_data as usize;
            let dst_start = section.s_virtual_address as usize;
            let dst_end = dst_start + section.s_size_of_raw_data as usize;

            if dst_end > image_size || src_end > image.len() {
                continue; // <-- skip bad sections
            }

            image_base_slice[dst_start..dst_end].copy_from_slice(
                image
                    .get(src_start..src_end)
                    .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid section data"))?,
            );
        }
    }

    return Ok(image_base_ptr); // expected *mut u8 got *mut c_void.
}