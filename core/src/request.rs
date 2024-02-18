use error::{Error, Result};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use util::AsciiLowercaseTestExt;

const HOST: &[u8] = b"host";
const ORIGIN: &[u8] = b"origin";
const CONNECTION: &[u8] = b"connection";
const AUTHORIZATION: &[u8] = b"authorization";
const IF_MATCH: &[u8] = b"if-match";
const IF_NONE_MATCH: &[u8] = b"if-none-match";
const ACCEPT: &[u8] = b"accept";
const ACCEPT_ENCODING: &[u8] = b"accept-encoding";
const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const CONTENT_TYPE: &[u8] = b"content-type";
const CONTENT_LENGTH: &[u8] = b"content-length";
const CONTENT_ENCODING: &[u8] = b"content-encoding";
const COOKIE: &[u8] = b"cookie";
const EXPECT: &[u8] = b"expect";
const ACCESS_CONTROL_REQUEST_METHOD: &[u8] = b"access-control-request-method";
const ACCESS_CONTROL_REQUEST_HEADERS: &[u8] = b"access-control-request-headers";

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum HeaderName {
    Host,
    Origin,
    Connection,
    Authorization,
    IfMatch,
    IfNoneMatch,
    Accept,
    AcceptEncoding,
    TransferEncoding,
    ContentType,
    ContentLength,
    ContentEncoding,
    Cookie,
    Expect,
    AccessControlRequestMethod,
    AccessControlRequestHeaders,
    Other(&'static [u8]),
    Unknown(Vec<u8>),
}

impl HeaderName {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            HeaderName::Unknown(vec) => vec.as_slice(),
            _ => self.try_into().unwrap(),
        }
    }
    pub fn try_from_static(value: &'static [u8]) -> Result<Self> {
        value.try_into().or_else(|_| {
            if value.is_ascii_lowercase() {
                Ok(HeaderName::Other(value))
            } else {
                Err(Error::CustomHeaderNameNotLowercase(
                    String::from_utf8_lossy(value).to_string(),
                ))
            }
        })
    }
    pub fn owned(value: &[u8]) -> Self {
        value
            .try_into()
            .unwrap_or_else(|_| HeaderName::Unknown(value.to_ascii_lowercase()))
    }
}

impl Display for HeaderName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_slice().escape_ascii())
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for HeaderName {
    type Error = Error;

    fn try_from(value: &'a [u8; N]) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for HeaderName {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self> {
        if value.is_ascii_lowercase() {
            _try_from_lowercase(value, value)
        } else {
            _try_from_lowercase(value, value.to_ascii_lowercase().as_slice())
        }
    }
}

fn _try_from_lowercase(value: &[u8], lowercase: &[u8]) -> Result<HeaderName> {
    match lowercase {
        HOST => Ok(HeaderName::Host),
        ORIGIN => Ok(HeaderName::Origin),
        CONNECTION => Ok(HeaderName::Connection),
        AUTHORIZATION => Ok(HeaderName::Authorization),
        IF_MATCH => Ok(HeaderName::IfMatch),
        IF_NONE_MATCH => Ok(HeaderName::IfNoneMatch),
        ACCEPT => Ok(HeaderName::Accept),
        ACCEPT_ENCODING => Ok(HeaderName::AcceptEncoding),
        TRANSFER_ENCODING => Ok(HeaderName::TransferEncoding),
        CONTENT_TYPE => Ok(HeaderName::ContentType),
        CONTENT_LENGTH => Ok(HeaderName::ContentLength),
        CONTENT_ENCODING => Ok(HeaderName::ContentEncoding),
        COOKIE => Ok(HeaderName::Cookie),
        EXPECT => Ok(HeaderName::Expect),
        ACCESS_CONTROL_REQUEST_METHOD => Ok(HeaderName::AccessControlRequestMethod),
        ACCESS_CONTROL_REQUEST_HEADERS => Ok(HeaderName::AccessControlRequestHeaders),
        _ => Err(Error::UnknownHeaderName(value.escape_ascii().to_string())),
    }
}

impl TryFrom<&HeaderName> for &'static [u8] {
    type Error = Error;

    fn try_from(value: &HeaderName) -> Result<Self> {
        match value {
            HeaderName::Host => Ok(HOST),
            HeaderName::Origin => Ok(ORIGIN),
            HeaderName::Connection => Ok(CONNECTION),
            HeaderName::Authorization => Ok(AUTHORIZATION),
            HeaderName::IfMatch => Ok(IF_MATCH),
            HeaderName::IfNoneMatch => Ok(IF_NONE_MATCH),
            HeaderName::Accept => Ok(ACCEPT),
            HeaderName::AcceptEncoding => Ok(ACCEPT_ENCODING),
            HeaderName::TransferEncoding => Ok(TRANSFER_ENCODING),
            HeaderName::ContentType => Ok(CONTENT_TYPE),
            HeaderName::ContentLength => Ok(CONTENT_LENGTH),
            HeaderName::ContentEncoding => Ok(CONTENT_ENCODING),
            HeaderName::Cookie => Ok(COOKIE),
            HeaderName::Expect => Ok(EXPECT),
            HeaderName::AccessControlRequestMethod => Ok(ACCESS_CONTROL_REQUEST_METHOD),
            HeaderName::AccessControlRequestHeaders => Ok(ACCESS_CONTROL_REQUEST_HEADERS),
            HeaderName::Other(value) => Ok(value),
            HeaderName::Unknown(value) => {
                Err(Error::UnknownHeaderName(value.escape_ascii().to_string()))
            }
        }
    }
}

impl AsRef<[u8]> for HeaderName {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl TryFrom<&str> for HeaderName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let value = value.as_bytes();
        if value.is_ascii_lowercase() {
            value.try_into()
        } else {
            value.to_ascii_lowercase().as_slice().try_into()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_bytes() {
        assert_eq!(HOST.try_into(), Ok(HeaderName::Host));
        assert_eq!(ORIGIN.try_into(), Ok(HeaderName::Origin));
        assert_eq!(CONNECTION.try_into(), Ok(HeaderName::Connection));
        assert_eq!(AUTHORIZATION.try_into(), Ok(HeaderName::Authorization));
        assert_eq!(IF_MATCH.try_into(), Ok(HeaderName::IfMatch));
        assert_eq!(IF_NONE_MATCH.try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!(ACCEPT.try_into(), Ok(HeaderName::Accept));
        assert_eq!(ACCEPT_ENCODING.try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!(
            TRANSFER_ENCODING.try_into(),
            Ok(HeaderName::TransferEncoding)
        );
        assert_eq!(CONTENT_TYPE.try_into(), Ok(HeaderName::ContentType));
        assert_eq!(CONTENT_LENGTH.try_into(), Ok(HeaderName::ContentLength));
        assert_eq!(CONTENT_ENCODING.try_into(), Ok(HeaderName::ContentEncoding));
        assert_eq!(COOKIE.try_into(), Ok(HeaderName::Cookie));
        assert_eq!(EXPECT.try_into(), Ok(HeaderName::Expect));
        assert_eq!(
            ACCESS_CONTROL_REQUEST_METHOD.try_into(),
            Ok(HeaderName::AccessControlRequestMethod)
        );
        assert_eq!(
            ACCESS_CONTROL_REQUEST_HEADERS.try_into(),
            Ok(HeaderName::AccessControlRequestHeaders)
        );
        let unknown: Result<HeaderName> = b"UNKNOWN".try_into();
        assert!(unknown.is_err());
        let unknown: Result<HeaderName> = HeaderName::try_from_static(b"Unknown");
        assert!(unknown.is_err());
        assert_eq!(HeaderName::try_from_static(b"Host"), Ok(HeaderName::Host));
        assert_eq!(
            HeaderName::try_from_static(b"origin"),
            Ok(HeaderName::Origin)
        );
        assert_eq!(
            HeaderName::try_from_static(b"unknown"),
            Ok(HeaderName::Other(b"unknown"))
        );
        assert_eq!(HeaderName::owned(b"HOST").try_into(), Ok(HeaderName::Host));
        assert_eq!(
            HeaderName::owned(b"accept").try_into(),
            Ok(HeaderName::Accept)
        );
        assert_eq!(
            HeaderName::owned(b"Unknown").try_into(),
            Ok(HeaderName::Unknown(b"unknown".to_vec()))
        );
        assert_eq!(
            HeaderName::owned(b"unknown").try_into(),
            Ok(HeaderName::Unknown(b"unknown".to_vec()))
        );
    }

    #[test]
    fn from_str() {
        assert_eq!("Host".try_into(), Ok(HeaderName::Host));
        assert_eq!("host".try_into(), Ok(HeaderName::Host));
        assert_eq!("HOST".try_into(), Ok(HeaderName::Host));
        assert_eq!("Origin".try_into(), Ok(HeaderName::Origin));
        assert_eq!("origin".try_into(), Ok(HeaderName::Origin));
        assert_eq!("ORIGIN".try_into(), Ok(HeaderName::Origin));
        assert_eq!("Connection".try_into(), Ok(HeaderName::Connection));
        assert_eq!("connection".try_into(), Ok(HeaderName::Connection));
        assert_eq!("CONNECTION".try_into(), Ok(HeaderName::Connection));
        assert_eq!("Authorization".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("authorization".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("AUTHORIZATION".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("If-Match".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!("if-match".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!("IF-MATCH".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!("If-None-Match".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("if-none-match".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("IF-NONE-MATCH".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("Accept".try_into(), Ok(HeaderName::Accept));
        assert_eq!("accept".try_into(), Ok(HeaderName::Accept));
        assert_eq!("ACCEPT".try_into(), Ok(HeaderName::Accept));
        assert_eq!("Accept-Encoding".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!("accept-encoding".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!("ACCEPT-ENCODING".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!(
            "Transfer-Encoding".try_into(),
            Ok(HeaderName::TransferEncoding)
        );
        assert_eq!(
            "transfer-encoding".try_into(),
            Ok(HeaderName::TransferEncoding)
        );
        assert_eq!(
            "TRANSFER-ENCODING".try_into(),
            Ok(HeaderName::TransferEncoding)
        );
        assert_eq!("Content-Type".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("content-type".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("CONTENT-TYPE".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("Content-Length".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!("content-length".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!("CONTENT-LENGTH".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!(
            "Content-Encoding".try_into(),
            Ok(HeaderName::ContentEncoding)
        );
        assert_eq!(
            "content-encoding".try_into(),
            Ok(HeaderName::ContentEncoding)
        );
        assert_eq!(
            "CONTENT-ENCODING".try_into(),
            Ok(HeaderName::ContentEncoding)
        );
        assert_eq!("Cookie".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("cookie".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("COOKIE".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("Expect".try_into(), Ok(HeaderName::Expect));
        assert_eq!("expect".try_into(), Ok(HeaderName::Expect));
        assert_eq!("EXPECT".try_into(), Ok(HeaderName::Expect));
        assert_eq!(
            "Access-Control-Request-Method".try_into(),
            Ok(HeaderName::AccessControlRequestMethod)
        );
        assert_eq!(
            "access-control-request-method".try_into(),
            Ok(HeaderName::AccessControlRequestMethod)
        );
        assert_eq!(
            "ACCESS-CONTROL-REQUEST-METHOD".try_into(),
            Ok(HeaderName::AccessControlRequestMethod)
        );
        assert_eq!(
            "Access-Control-Request-Headers".try_into(),
            Ok(HeaderName::AccessControlRequestHeaders)
        );
        assert_eq!(
            "access-control-request-headers".try_into(),
            Ok(HeaderName::AccessControlRequestHeaders)
        );
        assert_eq!(
            "ACCESS-CONTROL-REQUEST-HEADERS".try_into(),
            Ok(HeaderName::AccessControlRequestHeaders)
        );
        let unknown: Result<HeaderName> = "UNKNOWN".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn as_ref() {
        assert_eq!(HeaderName::Host.as_ref(), HOST);
        assert_eq!(HeaderName::Origin.as_ref(), ORIGIN);
        assert_eq!(HeaderName::Connection.as_ref(), CONNECTION);
        assert_eq!(HeaderName::Authorization.as_ref(), AUTHORIZATION);
        assert_eq!(HeaderName::IfMatch.as_ref(), IF_MATCH);
        assert_eq!(HeaderName::IfNoneMatch.as_ref(), IF_NONE_MATCH);
        assert_eq!(HeaderName::Accept.as_ref(), ACCEPT);
        assert_eq!(HeaderName::AcceptEncoding.as_ref(), ACCEPT_ENCODING);
        assert_eq!(HeaderName::TransferEncoding.as_ref(), TRANSFER_ENCODING);
        assert_eq!(HeaderName::ContentType.as_ref(), CONTENT_TYPE);
        assert_eq!(HeaderName::ContentLength.as_ref(), CONTENT_LENGTH);
        assert_eq!(HeaderName::ContentEncoding.as_ref(), CONTENT_ENCODING);
        assert_eq!(HeaderName::Cookie.as_ref(), COOKIE);
        assert_eq!(HeaderName::Expect.as_ref(), EXPECT);
        assert_eq!(
            HeaderName::AccessControlRequestMethod.as_ref(),
            ACCESS_CONTROL_REQUEST_METHOD
        );
        assert_eq!(
            HeaderName::AccessControlRequestHeaders.as_ref(),
            ACCESS_CONTROL_REQUEST_HEADERS
        );
        assert_eq!(
            HeaderName::try_from_static(b"unknown").unwrap().as_ref(),
            b"unknown"
        );
        assert_eq!(
            &HeaderName::try_from_static(b"unknown").unwrap().as_ref(),
            b"unknown"
        );
    }
}
