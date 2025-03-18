// Concatenates two slices of bytes
pub fn concat_slices(slice1: &[u8], slice2: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(slice1.len() + slice2.len()); // Pre-allocate memory
    result.extend_from_slice(slice1); // Append the first slice
    result.extend_from_slice(slice2); // Append the second slice

    result // Return the concatenated vector
}
