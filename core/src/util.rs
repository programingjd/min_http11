pub trait AsciiLowercaseTestExt {
    fn is_ascii_lowercase(&self) -> bool;
}

const DASH: u8 = b'-';
const UNDERSCORE: u8 = b'_';

impl AsciiLowercaseTestExt for [u8] {
    fn is_ascii_lowercase(&self) -> bool {
        self.iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == DASH || b == UNDERSCORE)
    }
}
