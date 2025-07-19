use std::io;

use clap::{Parser};

use crate::{
    args::WinPackageArgs, 
    headers::{
        dos::{self, ImageDOSHeader}, 
        windows::{ImageNTHeader32, ImageNTHeader64, ImageSectionHeader}
    }
};

mod headers;
mod args;
mod cast;
///
/// Tries to deserialze only 32-bit PE image structures
/// returns Optional value of [ImageNTHeader32](headers::windows::ImageNTHeader32)
/// struct
/// 
/// Contains unsafe scopes used for bytes reinterpretation
/// 
// try implement it more safe than C++ style
fn get_nt_header_32(image: &[u8]) -> io::Result<&ImageNTHeader32> {
    let dos_header = image
        .get(0..std::mem::size_of::<ImageDOSHeader>())
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unable to deserialize image at 1 stage"
        ))?;
    
    let dos_header = cast::unsafe_cast::<ImageDOSHeader>(dos_header);

    if dos_header.e_magic != 0x5A4D {
        // maybe obj or corrupted PE image
        return Err(io::Error::new(io::ErrorKind::InvalidData, "MZ signature not found"));
    }
    
    let offset: usize = dos_header.e_lfanew as usize;
    let nt_header_32= image
        .get(offset..(offset + std::mem::size_of::<ImageNTHeader32>()))
        .ok_or(
            io::Error::new(
                io::ErrorKind::InvalidData, 
                "Unable to deserialize image at stage 2"
            ))?;

    let nt_header_32 = cast::unsafe_cast::<ImageNTHeader32>(nt_header_32);

    if nt_header_32.nt_magic != 0x00004550 {
        // really corrupted PE image
        // Windows executables loader can't load it
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PE signature not found"));
    }

    return Ok(nt_header_32);
}
///
/// Tries to deserialze only 64-bit PE image structures
/// returns Optional value of [ImageNTHeader32](headers::windows::ImageNTHeader32)
/// struct
/// 
/// Contains unsafe scopes used for bytes reinterpretation
/// 
// try implement it more safe than C++ style
fn get_nt_header_64(image: &[u8]) -> io::Result<&ImageNTHeader64> {
    let dos_header_bytes = image
        .get(0..std::mem::size_of::<ImageDOSHeader>())
        .ok_or(
            io::Error::new(
                io::ErrorKind::InvalidData, 
                "Unable to deserialize PE image at stage 1"
            ))?;
    
    let dos_header = cast::unsafe_cast::<ImageDOSHeader>(dos_header_bytes);
    
    if dos_header.e_magic != 0x5A4D {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData, "signature MZ not found"));
    }

    let offset: usize = dos_header.e_lfanew as usize;
    let nt_header_bytes = image
        .get(offset..(offset + std::mem::size_of::<ImageNTHeader64>()))
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unable to deserialize PE image at stage 2"
        ))?;
    
    let nt_header = cast::unsafe_cast::<ImageNTHeader64>(nt_header_bytes);
    
    if nt_header.nt_magic != 0x00004550 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "signature PE not found"));
    }

    return Ok(nt_header);
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
/// Hint: use smart pointers
/// 
fn get_packed_section_32<'struct_ref_time>(
    image: &'struct_ref_time [u8], 
    nt_header: &'struct_ref_time ImageNTHeader32) -> io::Result<&'struct_ref_time ImageSectionHeader> {
    
    let sections_offset = 
        nt_header as *const _ as usize - image.as_ptr() as usize
        + std::mem::size_of::<ImageNTHeader32>();
    
    // headers_scope = N * section_head_len
    let sections_count = nt_header.nt_file_header.e_number_of_sections as usize;
    let sections_bytes = image
        .get(sections_offset..(sections_offset + (sections_count * std::mem::size_of::<ImageSectionHeader>())))
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unable to find sections scope"
        ))?; // val like C# nullable ctx fields
    
    let sections_slice: &[ImageSectionHeader] = cast::unsafe_slice_cast::<ImageSectionHeader>(sections_bytes, sections_count);
    let no_sections_err: io::Error = io::Error::new(
        io::ErrorKind::NotFound,
        "Unable to find PE sections"
    );

    return sections_slice
        .iter() // cast Iterator<T> instance
        .find(|h| h.s_name.starts_with(b".packed"))
        .ok_or(no_sections_err);
}

fn main() {
    // Necessary parts
    // 
    // 1) PE image structure checkout
    // 2) Attack Attack!
    // 3) .packed sections checkout
    // 4) static imports existance
    let argv: WinPackageArgs = WinPackageArgs::parse();

}