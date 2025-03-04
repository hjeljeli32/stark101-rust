// Concatenates two arrays of 32 bytes
pub fn concatenate_arrays(arr1: &[u8; 32], arr2: &[u8; 32]) -> [u8; 64] {
    let mut result = [0u8; 64]; 
    result[..32].copy_from_slice(arr1); 
    result[32..].copy_from_slice(arr2); 
    result
}