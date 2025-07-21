use crate::headers::{dos::{self, ImageDOSHeader}, windows::{self, *}};
use std::io;
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
            Self::Machine32Bit(nt) => nt.nt_file_header.e_number_of_sections,
            Self::Machine64Bit(nt) => nt.nt_file_header.e_number_of_sections
        }
    }
    pub fn get_image_size(&self) -> u32 {
        match self {
            Self::Machine32Bit(nt) => nt.nt_optional_header.e_size_of_image,
            Self::Machine64Bit(nt) => nt.nt_optional_header.e_size_of_image,
            
        }
    }
    pub fn get_image_base(&self) -> u32 {
        match self {
            Self::Machine32Bit(nt) => nt.nt_optional_header.e_image_base,
            Self::Machine64Bit(nt) => nt.nt_optional_header.e_image_base
        }
    }
    pub fn get_import_static_directory(&self) -> ImageDirectory {
        match self {
            Self::Machine32Bit(nt) => nt.nt_optional_header.e_import_static_directory,
            Self::Machine64Bit(nt) => nt.nt_optional_header.e_import_static_directory
        }
    }
    pub fn get_optional_header_size(&self) -> u16 {
        match self {
            Self::Machine32Bit(nt) => nt.nt_file_header.e_size_of_optional_header,
            Self::Machine64Bit(nt) => nt.nt_file_header.e_size_of_optional_header
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
fn try_get_nt_header(image: &[u8]) -> io::Result<NTHeaderType> {
    let mz_header = bytemuck::from_bytes::<ImageDOSHeader>(image
        .get(..std::mem::size_of::<ImageDOSHeader>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: invalid DOS header size"))?
    );

    if mz_header.e_magic != dos::IMAGE_DOS_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "stopped: DOS part is incompat"));
    }

    let nt_header_offset = mz_header.e_lfanew as usize;
    let nt_magic_bytes = image
        .get(nt_header_offset..nt_header_offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: NT header out of bounds"))?;


    if nt_magic_bytes != b"PE\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stopped: PE image signature not compatible"
        ));
    }
    let optional_magic_offset = nt_header_offset + windows::NT_OPTIONAL_HEADER_OFFSET;
    let optional_magic_bytes = image.get(optional_magic_offset..optional_magic_offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: Optional header out of bounds"))?;
    
    // PE32/+ sign matching
    match u16::from_le_bytes(optional_magic_bytes.try_into().unwrap()) {
        windows::IMAGE_NT_32_SIGNATURE => {
            let header = *bytemuck::from_bytes::<ImageNTHeader32>(image
                    .get(optional_magic_offset..std::mem::size_of::<ImageNTHeader32>()) 
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: PE32 header incomplete"))?
            );
            Ok(NTHeaderType::Machine32Bit(header))
        },
        windows::IMAGE_NT_64_SIGNATURE => {
            let header = *bytemuck::from_bytes(image
                .get(optional_magic_offset..std::mem::size_of::<ImageNTHeader64>())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stopped: PE32+ header incomplete"))?
            );
            Ok(NTHeaderType::Machine64Bit(header))
        }
        magic => Err(io::Error::new(io::ErrorKind::InvalidData, format!("stopped: signature extra mismatch {:X}", magic)))
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
fn try_get_packed_section(
    image: &[u8], 
    nt_header: &NTHeaderType) -> io::Result<Rc::<ImageSectionHeader>> {
    
    let sections_offset = 
        nt_header as *const _ as usize - image.as_ptr() as usize
        + std::mem::size_of::<ImageNTHeader32>();
    
    // headers_scope = N * section_head_len
    let sections_count = nt_header.get_number_of_sections() as usize;
    let sections_bytes = image
        .get(sections_offset..(sections_offset + (sections_count * std::mem::size_of::<ImageSectionHeader>())))
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "stopped: unable to find sections scope"
        ))?;
    
    let sections_slice = bytemuck::cast_slice::<u8, ImageSectionHeader>(sections_bytes);

    let no_sections_err: io::Error = io::Error::new(
        io::ErrorKind::NotFound,
        "stopped: unable to find PE sections"
    );
    let result = *sections_slice
            .iter() // cast Iterator<T> instance
            .find(|h| h.s_name.starts_with(b".packed"))
            .ok_or(no_sections_err)?;

    return Ok(Rc::new(result));
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
fn try_decrypt_image(packed_section: ImageSectionHeader, image_base: &[u8], mask: &[u8]) -> io::Result<Vec<u8>>{
    let extraction_err = io::Error::new(
        io::ErrorKind::InvalidData,
        "out of bounds .packed"
    );
    let unpack_err = io::Error::new(
        io::ErrorKind::InvalidData,
        "unpacked section corrupted"
    );

    let start = packed_section.s_virtual_address as usize;
    let end = start + packed_section.m_virtual_size as usize;

    let section_data = image_base
        .get(start..end)
        .ok_or(extraction_err)?;

    let unpacked_size = section_data
        .get(0..8)
        .map(|r| bytemuck::pod_read_unaligned::<usize>(r))
        .expect("stopped: bad unpacked size.");

    let compressed_data = &section_data[8..]; // take slice from 8th element till the end.

    // warning.
    let decompressed = miniz_oxide::inflate::decompress_to_vec_zlib(compressed_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?; // <-- full report unpack_err instead

    match decompressed.len() != unpacked_size {
        true => {
            return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "stopped: processed sizes are different\r\n\texpected: {}\r\n\tgot{}",
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