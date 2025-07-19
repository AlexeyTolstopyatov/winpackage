use std::io;

use clap::Parser;

use crate::{
    args::WinPackageArgs, 
    headers::{
        dos::{self, ImageDOSHeader}, 
        windows::{ImageNTHeader32, ImageNTHeader64}
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
/// Tries to deserialze only 32-bit PE image structures
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
fn get_packed_section_32(image: &[u8], nt_header: &ImageNTHeader32) {
    
}

fn main() {
    let argv: WinPackageArgs = WinPackageArgs::parse();

}