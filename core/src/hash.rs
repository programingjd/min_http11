pub fn hash(message: &[u8]) -> u32 {
    crc32fast::hash(message)
}
