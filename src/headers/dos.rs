#[derive(Debug)]
///
/// Extended PC/MS-DOS header 
/// 
/// Contains MZ header (standard DOS header)
/// fields and special extended part added in
/// next versions of MS/PC-DOS
/// 
pub struct ImageDOSHeader {
    // Standard DOS header part (uses in BW-DOS)
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_checksum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16, // long file address relocations
    pub e_ovno: u16,
    
    // Extended part starts here (not uses in BW-DOS)
    pub e_res1: u16,
    pub e_res2: u16,
    pub e_res3: u16,
    pub e_res4: u16,
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res: [u16; 10],
    pub e_lfanew: u32 // ULONG file address NE magic
}