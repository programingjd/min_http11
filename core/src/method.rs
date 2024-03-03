use crate::error::{Error, Result};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};

const GET: &[u8] = b"GET";
const HEAD: &[u8] = b"HEAD";
const POST: &[u8] = b"POST";
const PUT: &[u8] = b"PUT";
const DELETE: &[u8] = b"DELETE";
const OPTIONS: &[u8] = b"OPTIONS";
const PATCH: &[u8] = b"PATCH";

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Other(&'static [u8]),
}

impl Method {
    pub fn as_slice(&self) -> &'static [u8] {
        self.into()
    }
    pub fn from_static(value: &'static [u8]) -> Self {
        value.try_into().unwrap_or(Method::Other(value))
    }
    pub fn can_have_body(&self) -> bool {
        !matches!(self, Method::Get | Method::Head | Method::Options)
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_slice().escape_ascii())
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for Method {
    type Error = Error;

    fn try_from(value: &'a [u8; N]) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Method {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self> {
        match value {
            GET => Ok(Method::Get),
            HEAD => Ok(Method::Head),
            POST => Ok(Method::Post),
            PUT => Ok(Method::Put),
            DELETE => Ok(Method::Delete),
            OPTIONS => Ok(Method::Options),
            PATCH => Ok(Method::Patch),
            other => Err(Error::UnknownMethod(other.escape_ascii().to_string())),
        }
    }
}

impl From<&Method> for &'static [u8] {
    fn from(value: &Method) -> Self {
        match value {
            Method::Get => GET,
            Method::Head => HEAD,
            Method::Post => POST,
            Method::Put => PUT,
            Method::Delete => DELETE,
            Method::Options => OPTIONS,
            Method::Patch => PATCH,
            Method::Other(value) => value,
        }
    }
}

impl AsRef<[u8]> for Method {
    fn as_ref(&self) -> &'static [u8] {
        self.into()
    }
}

impl TryFrom<&str> for Method {
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
        assert_eq!(GET.try_into(), Ok(Method::Get));
        assert_eq!(HEAD.try_into(), Ok(Method::Head));
        assert_eq!(POST.try_into(), Ok(Method::Post));
        assert_eq!(PUT.try_into(), Ok(Method::Put));
        assert_eq!(DELETE.try_into(), Ok(Method::Delete));
        assert_eq!(OPTIONS.try_into(), Ok(Method::Options));
        assert_eq!(PATCH.try_into(), Ok(Method::Patch));
        let unknown: Result<Method> = b"UNKNOWN".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn from_str() {
        assert_eq!("GET".try_into(), Ok(Method::Get));
        assert_eq!("HEAD".try_into(), Ok(Method::Head));
        assert_eq!("POST".try_into(), Ok(Method::Post));
        assert_eq!("PUT".try_into(), Ok(Method::Put));
        assert_eq!("DELETE".try_into(), Ok(Method::Delete));
        assert_eq!("OPTIONS".try_into(), Ok(Method::Options));
        assert_eq!("PATCH".try_into(), Ok(Method::Patch));
        let unknown: Result<Method> = "UNKNOWN".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn as_ref() {
        assert_eq!(Method::Get.as_ref(), GET);
        assert_eq!(Method::Head.as_ref(), HEAD);
        assert_eq!(Method::Post.as_ref(), POST);
        assert_eq!(Method::Put.as_ref(), PUT);
        assert_eq!(Method::Delete.as_ref(), DELETE);
        assert_eq!(Method::Options.as_ref(), OPTIONS);
        assert_eq!(Method::Patch.as_ref(), PATCH);
        assert_eq!(Method::from_static(b"UNKNOWN").as_ref(), b"UNKNOWN")
    }
}
