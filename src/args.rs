use std::path::PathBuf;

///
/// Arguments vector for this app. All parameters non-Optional
/// 
#[derive(clap::Parser)]
pub struct WinPackageArgs {
    ///
    /// Decompress image and run Win32 process from allocated memory.
    /// 
    /// This procedure not saves decompressed image as file.
    /// Procedure just rewrites image in RAM and runs it using Windows API 
    ///  
    #[arg(short, long)]
    pub decompress: PathBuf,
    ///
    /// This procedure just compresses (rewrites) image by current path.
    /// > [!WARNING] 
    /// > This procedure REWRITES your image. 
    /// 
    #[arg(short, long)]
    pub compress: PathBuf,
    ///
    /// Special keyword used for rewriting
    /// PE image information. 
    /// 
    #[arg(short, long)]
    ///
    /// Key has length about 16-bytes.
    /// # Conditions ignoring: MORE
    /// > [!WARNING] 
    /// > Key turncates right. (i.e. "optional_header" => "optional"_header)
    /// 
    /// # Conditions ignoring: LESS
    /// > [!WARNING] 
    /// > Key turncates rights too (i.e. "pack" => "packAAAA")
    /// 
    pub key: String          // special XOR keyword used by sections compressor.
}