///
/// Mandatory translate kind of bytes as other kind of those bytes
/// Litrally reinterpret_cast<T>
///  
pub fn unsafe_cast<S> (bytes: &[u8]) -> &S {
    let structure = unsafe {
        &*(bytes.as_ptr() as *const S)
    };

    return structure;
}
///
/// Applies when unmanaged data type _arrays_
/// deserializes.
/// 
pub fn unsafe_slice_cast<S>(bytes: &[u8], length: usize) -> &[S] {
    let slice = unsafe {
        std::slice::from_raw_parts(
            bytes.as_ptr() as *const S, 
            length)
    };

    return slice;
}
