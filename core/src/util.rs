pub trait AsciiLowercaseTestExt {
    fn is_ascii_lowercase(&self) -> bool;
}

impl AsciiLowercaseTestExt for [u8] {
    fn is_ascii_lowercase(&self) -> bool {
        self.iter().all(|&b| b.is_ascii_lowercase())
    }
}
