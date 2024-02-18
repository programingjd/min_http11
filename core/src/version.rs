use error::{Error, Result};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};

const HTTP11: &[u8] = b"HTTP/1.1";

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Version {
    Http11,
    Unsupported(&'static [u8]),
}

impl Version {
    pub fn as_slice(&self) -> &'static [u8] {
        self.into()
    }
    pub fn from_static(value: &'static [u8]) -> Self {
        value
            .try_into()
            .unwrap_or_else(|_| Version::Unsupported(value))
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_slice().escape_ascii())
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for Version {
    type Error = Error;

    fn try_from(value: &'a [u8; N]) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Version {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self> {
        match value {
            HTTP11 => Ok(Version::Http11),
            other => Err(Error::UnsupportedVersion(other.escape_ascii().to_string())),
        }
    }
}

impl From<&Version> for &'static [u8] {
    fn from(value: &Version) -> Self {
        match value {
            Version::Http11 => HTTP11,
            Version::Unsupported(value) => value,
        }
    }
}

impl AsRef<[u8]> for Version {
    fn as_ref(&self) -> &'static [u8] {
        self.into()
    }
}

impl TryFrom<&str> for Version {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        value.as_bytes().try_into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_bytes() {
        assert_eq!(HTTP11.try_into(), Ok(Version::Http11));
        let unknown: Result<Version> = b"HTTP/1.0".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn from_str() {
        assert_eq!("HTTP/1.1".try_into(), Ok(Version::Http11));
        let unknown: Result<Version> = "UNKNOWN".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn as_ref() {
        assert_eq!(Version::Http11.as_ref(), HTTP11);
        assert_eq!(Version::from_static(b"HTTP/2").as_ref(), b"HTTP/2")
    }
}
