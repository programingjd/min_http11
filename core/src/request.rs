use crate::error::{Error, Result};
use crate::util::AsciiLowercaseTestExt;
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};

mod minimal {
    #[cfg(feature = "_minimal")]
    use crate::error::{Error, Result};
    #[cfg(feature = "_minimal")]
    use crate::hash::hash;

    pub const CONTENT_LENGTH: &[u8] = b"content-length";
    pub const HOST: &[u8] = b"host";
    pub const IF_MATCH: &[u8] = b"if-match";
    pub const IF_NONE_MATCH: &[u8] = b"if-none-match";
    pub const X_HUB_SIGNATURE_256: &[u8] = b"x-hub-signature-256";

    pub const CONTENT_LENGTH_HASH: u32 = 314322716;
    pub const HOST_HASH: u32 = 3475444733;
    pub const IF_MATCH_HASH: u32 = 1168849366;
    pub const IF_NONE_MATCH_HASH: u32 = 1529156225;
    pub const X_HUB_SIGNATURE_256_HASH: u32 = 1932839174;

    #[cfg(feature = "_minimal")]
    #[derive(Default)]
    pub struct KnownHeaders<'a> {
        pub content_length: Option<&'a [u8]>,
        pub host: Option<&'a [u8]>,
        pub if_match: Option<&'a [u8]>,
        pub if_none_match: Option<&'a [u8]>,
        pub x_hub_signature_256_hash: Option<&'a [u8]>,
    }

    #[cfg(feature = "_minimal")]
    #[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
    pub enum HeaderName {
        ContentLength,
        Host,
        IfMatch,
        IfNoneMatch,
        XHubSignature256,

        Other(&'static [u8]),
        Unknown(Vec<u8>),
    }

    #[cfg(feature = "_minimal")]
    pub(crate) fn _try_from_lowercase(value: &[u8], lowercase: &[u8]) -> Result<HeaderName> {
        match hash(lowercase) {
            CONTENT_LENGTH_HASH if lowercase == CONTENT_LENGTH => Ok(HeaderName::ContentLength),
            HOST_HASH if lowercase == HOST => Ok(HeaderName::Host),
            IF_MATCH_HASH if lowercase == IF_MATCH => Ok(HeaderName::IfMatch),
            IF_NONE_MATCH_HASH if lowercase == IF_NONE_MATCH => Ok(HeaderName::IfNoneMatch),
            X_HUB_SIGNATURE_256_HASH if lowercase == X_HUB_SIGNATURE_256 => {
                Ok(HeaderName::XHubSignature256)
            }
            _ => Err(Error::UnknownHeaderName(value.escape_ascii().to_string())),
        }
    }

    #[cfg(feature = "_minimal")]
    impl TryFrom<&HeaderName> for &'static [u8] {
        type Error = Error;

        fn try_from(value: &HeaderName) -> Result<Self> {
            match value {
                HeaderName::ContentLength => Ok(CONTENT_LENGTH),
                HeaderName::Host => Ok(HOST),
                HeaderName::IfMatch => Ok(IF_MATCH),
                HeaderName::IfNoneMatch => Ok(IF_NONE_MATCH),
                HeaderName::XHubSignature256 => Ok(X_HUB_SIGNATURE_256),
                HeaderName::Other(value) => Ok(value),
                HeaderName::Unknown(value) => {
                    Err(Error::UnknownHeaderName(value.escape_ascii().to_string()))
                }
            }
        }
    }
}

#[cfg(not(feature = "_minimal"))]
mod others {
    use super::minimal::*;
    use crate::error::{Error, Result};
    use crate::hash::hash;
    use crate::request::{
        CONTENT_LENGTH_HASH, HOST_HASH, IF_MATCH_HASH, IF_NONE_MATCH_HASH, X_HUB_SIGNATURE_256_HASH,
    };

    pub const ACCEPT: &[u8] = b"accept";
    pub const ACCEPT_ENCODING: &[u8] = b"accept-encoding";
    pub const ACCEPT_LANGUAGE: &[u8] = b"accept-language";
    pub const ACCESS_CONTROL_REQUEST_HEADERS: &[u8] = b"access-control-request-headers";
    pub const ACCESS_CONTROL_REQUEST_METHOD: &[u8] = b"access-control-request-method";
    pub const AUTHORIZATION: &[u8] = b"authorization";
    pub const CONNECTION: &[u8] = b"connection";
    pub const CONTENT_ENCODING: &[u8] = b"content-encoding";
    pub const CONTENT_TYPE: &[u8] = b"content-type";
    pub const COOKIE: &[u8] = b"cookie";
    pub const EXPECT: &[u8] = b"expect";
    pub const IF_MODIFIED_SINCE: &[u8] = b"if-modified-since";
    pub const IF_RANGE: &[u8] = b"if-range";
    pub const IF_UNMODIFIED_SINCE: &[u8] = b"if-unmodified-since";
    pub const ORIGIN: &[u8] = b"origin";
    pub const RANGE: &[u8] = b"range";
    pub const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
    pub const USER_AGENT: &[u8] = b"user-agent";
    pub const X_CSRF_TOKEN: &[u8] = b"x-csrf-token";
    pub const X_FORWARDED_FOR: &[u8] = b"x-forwarded-for";
    pub const X_FORWARDED_HOST: &[u8] = b"x-forwarded-host";
    pub const X_REAL_IP: &[u8] = b"x-real-ip";

    pub const ACCEPT_HASH: u32 = 3005279540;
    pub const ACCEPT_ENCODING_HASH: u32 = 2687938133;
    pub const ACCEPT_LANGUAGE_HASH: u32 = 480585391;
    pub const ACCESS_CONTROL_REQUEST_HEADERS_HASH: u32 = 3862518975;
    pub const ACCESS_CONTROL_REQUEST_METHOD_HASH: u32 = 1698782395;
    pub const AUTHORIZATION_HASH: u32 = 2053999599;
    pub const CONNECTION_HASH: u32 = 704082790;
    pub const CONTENT_ENCODING_HASH: u32 = 3836410099;
    pub const CONTENT_TYPE_HASH: u32 = 3266185539;
    pub const COOKIE_HASH: u32 = 2329983590;
    pub const EXPECT_HASH: u32 = 482521170;
    pub const IF_MODIFIED_SINCE_HASH: u32 = 1848278858;
    pub const IF_RANGE_HASH: u32 = 2893522586;
    pub const IF_UNMODIFIED_SINCE_HASH: u32 = 462614015;
    pub const ORIGIN_HASH: u32 = 3740358174;
    pub const RANGE_HASH: u32 = 2475121225;
    pub const TRANSFER_ENCODING_HASH: u32 = 1470906230;
    pub const USER_AGENT_HASH: u32 = 2191772431;
    pub const X_CSRF_TOKEN_HASH: u32 = 3276872746;
    pub const X_FORWARDED_FOR_HASH: u32 = 2397052407;
    pub const X_FORWARDED_HOST_HASH: u32 = 1610193784;
    pub const X_REAL_IP_HASH: u32 = 3988930344;

    #[derive(Default)]
    pub struct KnownHeaders<'a> {
        pub accept: Option<&'a [u8]>,
        pub accept_encoding: Option<&'a [u8]>,
        pub accept_language: Option<&'a [u8]>,
        pub access_control_request_headers: Option<&'a [u8]>,
        pub access_control_request_method: Option<&'a [u8]>,
        pub authorization: Option<&'a [u8]>,
        pub connection: Option<&'a [u8]>,
        pub content_encoding: Option<&'a [u8]>,
        pub content_length: Option<&'a [u8]>,
        pub content_type: Option<&'a [u8]>,
        pub cookie: Option<&'a [u8]>,
        pub expect: Option<&'a [u8]>,
        pub host: Option<&'a [u8]>,
        pub if_match: Option<&'a [u8]>,
        pub if_modified_since: Option<&'a [u8]>,
        pub if_none_match: Option<&'a [u8]>,
        pub if_range: Option<&'a [u8]>,
        pub if_unmodified_since: Option<&'a [u8]>,
        pub origin: Option<&'a [u8]>,
        pub range: Option<&'a [u8]>,
        pub transfer_encoding: Option<&'a [u8]>,
        pub user_agent: Option<&'a [u8]>,
        pub x_csrf_token: Option<&'a [u8]>,
        pub x_forwarded_for: Option<&'a [u8]>,
        pub x_forwarded_host: Option<&'a [u8]>,
        pub x_read_ip: Option<&'a [u8]>,
        pub x_hub_signature_256_hash: Option<&'a [u8]>,
    }

    #[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
    pub enum HeaderName {
        Accept,
        AcceptEncoding,
        AcceptLanguage,
        AccessControlRequestHeaders,
        AccessControlRequestMethod,
        Authorization,
        Connection,
        ContentEncoding,
        ContentLength,
        ContentType,
        Cookie,
        Expect,
        Host,
        IfMatch,
        IfModifiedSince,
        IfNoneMatch,
        IfRange,
        IfUnmodifiedSince,
        Origin,
        Range,
        TransferEncoding,
        UserAgent,
        XCSRFToken,
        XForwardedFor,
        XForwardedHost,
        XReadIp,
        XHubSignature256,

        Other(&'static [u8]),
        Unknown(Vec<u8>),
    }

    pub(crate) fn _try_from_lowercase(
        value: &[u8],
        lowercase: &[u8],
    ) -> Result<crate::request::HeaderName> {
        match hash(lowercase) {
            ACCEPT_HASH if lowercase == ACCEPT => Ok(crate::request::HeaderName::Accept),
            ACCEPT_ENCODING_HASH if lowercase == ACCEPT_ENCODING => {
                Ok(crate::request::HeaderName::AcceptEncoding)
            }
            ACCEPT_LANGUAGE_HASH if lowercase == ACCEPT_LANGUAGE => {
                Ok(crate::request::HeaderName::AcceptLanguage)
            }
            ACCESS_CONTROL_REQUEST_HEADERS_HASH if lowercase == ACCESS_CONTROL_REQUEST_HEADERS => {
                Ok(crate::request::HeaderName::AccessControlRequestHeaders)
            }
            ACCESS_CONTROL_REQUEST_METHOD_HASH if lowercase == ACCESS_CONTROL_REQUEST_METHOD => {
                Ok(crate::request::HeaderName::AccessControlRequestMethod)
            }
            AUTHORIZATION_HASH if lowercase == AUTHORIZATION => {
                Ok(crate::request::HeaderName::Authorization)
            }
            CONNECTION_HASH if lowercase == CONNECTION => {
                Ok(crate::request::HeaderName::Connection)
            }
            CONTENT_ENCODING_HASH if lowercase == CONTENT_ENCODING => {
                Ok(crate::request::HeaderName::ContentEncoding)
            }
            CONTENT_LENGTH_HASH if lowercase == CONTENT_LENGTH => {
                Ok(crate::request::HeaderName::ContentLength)
            }
            CONTENT_TYPE_HASH if lowercase == CONTENT_TYPE => {
                Ok(crate::request::HeaderName::ContentType)
            }
            COOKIE_HASH if lowercase == COOKIE => Ok(crate::request::HeaderName::Cookie),
            EXPECT_HASH if lowercase == EXPECT => Ok(crate::request::HeaderName::Expect),
            HOST_HASH if lowercase == HOST => Ok(crate::request::HeaderName::Host),
            IF_MATCH_HASH if lowercase == IF_MATCH => Ok(crate::request::HeaderName::IfMatch),
            IF_MODIFIED_SINCE_HASH if lowercase == IF_MODIFIED_SINCE => {
                Ok(crate::request::HeaderName::IfModifiedSince)
            }
            IF_NONE_MATCH_HASH if lowercase == IF_NONE_MATCH => {
                Ok(crate::request::HeaderName::IfNoneMatch)
            }
            IF_RANGE_HASH if lowercase == IF_RANGE => Ok(crate::request::HeaderName::IfRange),
            IF_UNMODIFIED_SINCE_HASH if lowercase == IF_UNMODIFIED_SINCE => {
                Ok(crate::request::HeaderName::IfUnmodifiedSince)
            }
            ORIGIN_HASH if lowercase == ORIGIN => Ok(crate::request::HeaderName::Origin),
            RANGE_HASH if lowercase == RANGE => Ok(crate::request::HeaderName::Range),
            TRANSFER_ENCODING_HASH if lowercase == TRANSFER_ENCODING => {
                Ok(crate::request::HeaderName::TransferEncoding)
            }
            USER_AGENT_HASH if lowercase == USER_AGENT => Ok(crate::request::HeaderName::UserAgent),
            X_CSRF_TOKEN_HASH if lowercase == X_CSRF_TOKEN => {
                Ok(crate::request::HeaderName::XCSRFToken)
            }
            X_FORWARDED_FOR_HASH if lowercase == X_FORWARDED_FOR => {
                Ok(crate::request::HeaderName::XForwardedFor)
            }
            X_FORWARDED_HOST_HASH if lowercase == X_FORWARDED_HOST => {
                Ok(crate::request::HeaderName::XForwardedHost)
            }
            X_HUB_SIGNATURE_256_HASH if lowercase == X_HUB_SIGNATURE_256 => {
                Ok(crate::request::HeaderName::XHubSignature256)
            }
            X_REAL_IP_HASH if lowercase == X_REAL_IP => Ok(crate::request::HeaderName::XReadIp),
            _ => Err(Error::UnknownHeaderName(value.escape_ascii().to_string())),
        }
    }

    impl TryFrom<&crate::request::HeaderName> for &'static [u8] {
        type Error = Error;

        fn try_from(value: &crate::request::HeaderName) -> Result<Self> {
            match value {
                crate::request::HeaderName::Accept => Ok(ACCEPT),
                crate::request::HeaderName::AcceptEncoding => Ok(ACCEPT_ENCODING),
                crate::request::HeaderName::AcceptLanguage => Ok(ACCEPT_LANGUAGE),
                crate::request::HeaderName::AccessControlRequestHeaders => {
                    Ok(ACCESS_CONTROL_REQUEST_HEADERS)
                }
                crate::request::HeaderName::AccessControlRequestMethod => {
                    Ok(ACCESS_CONTROL_REQUEST_METHOD)
                }
                crate::request::HeaderName::Authorization => Ok(AUTHORIZATION),
                crate::request::HeaderName::Connection => Ok(CONNECTION),
                crate::request::HeaderName::ContentEncoding => Ok(CONTENT_ENCODING),
                crate::request::HeaderName::ContentLength => Ok(CONTENT_LENGTH),
                crate::request::HeaderName::ContentType => Ok(CONTENT_TYPE),
                crate::request::HeaderName::Cookie => Ok(COOKIE),
                crate::request::HeaderName::Expect => Ok(EXPECT),
                crate::request::HeaderName::Host => Ok(HOST),
                crate::request::HeaderName::IfMatch => Ok(IF_MATCH),
                crate::request::HeaderName::IfModifiedSince => Ok(IF_MODIFIED_SINCE),
                crate::request::HeaderName::IfNoneMatch => Ok(IF_NONE_MATCH),
                crate::request::HeaderName::IfRange => Ok(IF_RANGE),
                crate::request::HeaderName::IfUnmodifiedSince => Ok(IF_UNMODIFIED_SINCE),
                crate::request::HeaderName::Origin => Ok(ORIGIN),
                crate::request::HeaderName::Range => Ok(RANGE),
                crate::request::HeaderName::TransferEncoding => Ok(TRANSFER_ENCODING),
                crate::request::HeaderName::UserAgent => Ok(USER_AGENT),
                crate::request::HeaderName::XCSRFToken => Ok(X_CSRF_TOKEN),
                crate::request::HeaderName::XForwardedFor => Ok(X_FORWARDED_FOR),
                crate::request::HeaderName::XForwardedHost => Ok(X_FORWARDED_HOST),
                crate::request::HeaderName::XReadIp => Ok(X_REAL_IP),
                crate::request::HeaderName::XHubSignature256 => Ok(X_HUB_SIGNATURE_256),
                crate::request::HeaderName::Other(value) => Ok(value),
                crate::request::HeaderName::Unknown(value) => {
                    Err(Error::UnknownHeaderName(value.escape_ascii().to_string()))
                }
            }
        }
    }
}

pub use minimal::*;
#[cfg(not(feature = "_minimal"))]
pub use others::*;

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
    pub fn owned(value: &[u8]) -> Result<Self> {
        match value.try_into() {
            Err(_) => {
                let lowercase = value.to_ascii_lowercase();
                if lowercase.is_ascii_lowercase() {
                    Ok(HeaderName::Unknown(value.to_ascii_lowercase()))
                } else {
                    Err(Error::InvalidHeaderName(value.escape_ascii().to_string()))
                }
            }
            it => it,
        }
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
#[cfg(not(feature = "_minimal"))]
mod test {
    use super::*;

    #[test]
    fn from_bytes() {
        assert_eq!(ACCEPT.try_into(), Ok(HeaderName::Accept));
        assert_eq!(ACCEPT_ENCODING.try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!(ACCEPT_LANGUAGE.try_into(), Ok(HeaderName::AcceptLanguage));
        assert_eq!(
            ACCESS_CONTROL_REQUEST_HEADERS.try_into(),
            Ok(HeaderName::AccessControlRequestHeaders)
        );
        assert_eq!(
            ACCESS_CONTROL_REQUEST_METHOD.try_into(),
            Ok(HeaderName::AccessControlRequestMethod)
        );
        assert_eq!(AUTHORIZATION.try_into(), Ok(HeaderName::Authorization));
        assert_eq!(CONNECTION.try_into(), Ok(HeaderName::Connection));
        assert_eq!(CONTENT_ENCODING.try_into(), Ok(HeaderName::ContentEncoding));
        assert_eq!(CONTENT_LENGTH.try_into(), Ok(HeaderName::ContentLength));
        assert_eq!(CONTENT_TYPE.try_into(), Ok(HeaderName::ContentType));
        assert_eq!(COOKIE.try_into(), Ok(HeaderName::Cookie));
        assert_eq!(EXPECT.try_into(), Ok(HeaderName::Expect));
        assert_eq!(HOST.try_into(), Ok(HeaderName::Host));
        assert_eq!(IF_MATCH.try_into(), Ok(HeaderName::IfMatch));
        assert_eq!(
            IF_MODIFIED_SINCE.try_into(),
            Ok(HeaderName::IfModifiedSince)
        );
        assert_eq!(IF_NONE_MATCH.try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!(IF_RANGE.try_into(), Ok(HeaderName::IfRange));
        assert_eq!(
            IF_UNMODIFIED_SINCE.try_into(),
            Ok(HeaderName::IfUnmodifiedSince)
        );
        assert_eq!(ORIGIN.try_into(), Ok(HeaderName::Origin));
        assert_eq!(RANGE.try_into(), Ok(HeaderName::Range));
        assert_eq!(
            TRANSFER_ENCODING.try_into(),
            Ok(HeaderName::TransferEncoding)
        );
        assert_eq!(USER_AGENT.try_into(), Ok(HeaderName::UserAgent));
        assert_eq!(X_CSRF_TOKEN.try_into(), Ok(HeaderName::XCSRFToken));
        assert_eq!(X_FORWARDED_FOR.try_into(), Ok(HeaderName::XForwardedFor));
        assert_eq!(X_FORWARDED_HOST.try_into(), Ok(HeaderName::XForwardedHost));
        assert_eq!(X_REAL_IP.try_into(), Ok(HeaderName::XReadIp));
        assert_eq!(
            X_HUB_SIGNATURE_256.try_into(),
            Ok(HeaderName::XHubSignature256)
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
        assert_eq!(
            HeaderName::owned(b"HOST").unwrap().try_into(),
            Ok(HeaderName::Host)
        );
        assert_eq!(
            HeaderName::owned(b"accept").unwrap().try_into(),
            Ok(HeaderName::Accept)
        );
        assert_eq!(
            HeaderName::owned(b"Unknown").unwrap().try_into(),
            Ok(HeaderName::Unknown(b"unknown".to_vec()))
        );
        assert_eq!(
            HeaderName::owned(b"unknown").unwrap().try_into(),
            Ok(HeaderName::Unknown(b"unknown".to_vec()))
        );
    }

    #[test]
    fn from_str() {
        assert_eq!("Accept".try_into(), Ok(HeaderName::Accept));
        assert_eq!("accept".try_into(), Ok(HeaderName::Accept));
        assert_eq!("ACCEPT".try_into(), Ok(HeaderName::Accept));
        assert_eq!("Accept-Encoding".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!("accept-encoding".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!("ACCEPT-ENCODING".try_into(), Ok(HeaderName::AcceptEncoding));
        assert_eq!("Accept-Language".try_into(), Ok(HeaderName::AcceptLanguage));
        assert_eq!("accept-language".try_into(), Ok(HeaderName::AcceptLanguage));
        assert_eq!("ACCEPT-LANGUAGE".try_into(), Ok(HeaderName::AcceptLanguage));
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
        assert_eq!("Authorization".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("authorization".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("AUTHORIZATION".try_into(), Ok(HeaderName::Authorization));
        assert_eq!("Connection".try_into(), Ok(HeaderName::Connection));
        assert_eq!("connection".try_into(), Ok(HeaderName::Connection));
        assert_eq!("CONNECTION".try_into(), Ok(HeaderName::Connection));
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
        assert_eq!("Content-Length".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!("content-length".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!("CONTENT-LENGTH".try_into(), Ok(HeaderName::ContentLength));
        assert_eq!("Content-Type".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("content-type".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("CONTENT-TYPE".try_into(), Ok(HeaderName::ContentType));
        assert_eq!("Cookie".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("cookie".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("COOKIE".try_into(), Ok(HeaderName::Cookie));
        assert_eq!("Expect".try_into(), Ok(HeaderName::Expect));
        assert_eq!("expect".try_into(), Ok(HeaderName::Expect));
        assert_eq!("EXPECT".try_into(), Ok(HeaderName::Expect));
        assert_eq!("Host".try_into(), Ok(HeaderName::Host));
        assert_eq!("host".try_into(), Ok(HeaderName::Host));
        assert_eq!("HOST".try_into(), Ok(HeaderName::Host));
        assert_eq!("If-Match".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!("if-match".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!("IF-MATCH".try_into(), Ok(HeaderName::IfMatch));
        assert_eq!(
            "If-Modified-Since".try_into(),
            Ok(HeaderName::IfModifiedSince)
        );
        assert_eq!(
            "if-modified-since".try_into(),
            Ok(HeaderName::IfModifiedSince)
        );
        assert_eq!(
            "IF-MODIFIED-SINCE".try_into(),
            Ok(HeaderName::IfModifiedSince)
        );
        assert_eq!("If-None-Match".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("if-none-match".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("IF-NONE-MATCH".try_into(), Ok(HeaderName::IfNoneMatch));
        assert_eq!("If-Range".try_into(), Ok(HeaderName::IfRange));
        assert_eq!("if-range".try_into(), Ok(HeaderName::IfRange));
        assert_eq!("IF-RANGE".try_into(), Ok(HeaderName::IfRange));
        assert_eq!(
            "If-Unmodified-Since".try_into(),
            Ok(HeaderName::IfUnmodifiedSince)
        );
        assert_eq!(
            "if-unmodified-since".try_into(),
            Ok(HeaderName::IfUnmodifiedSince)
        );
        assert_eq!(
            "IF-UNMODIFIED-SINCE".try_into(),
            Ok(HeaderName::IfUnmodifiedSince)
        );
        assert_eq!("Origin".try_into(), Ok(HeaderName::Origin));
        assert_eq!("origin".try_into(), Ok(HeaderName::Origin));
        assert_eq!("ORIGIN".try_into(), Ok(HeaderName::Origin));
        assert_eq!("Range".try_into(), Ok(HeaderName::Range));
        assert_eq!("range".try_into(), Ok(HeaderName::Range));
        assert_eq!("RANGE".try_into(), Ok(HeaderName::Range));
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
        assert_eq!("User-Agent".try_into(), Ok(HeaderName::UserAgent));
        assert_eq!("user-agent".try_into(), Ok(HeaderName::UserAgent));
        assert_eq!("USER-AGENT".try_into(), Ok(HeaderName::UserAgent));
        assert_eq!("X-CSRF-Token".try_into(), Ok(HeaderName::XCSRFToken));
        assert_eq!("x-csrf-token".try_into(), Ok(HeaderName::XCSRFToken));
        assert_eq!("X-CSRF-TOKEN".try_into(), Ok(HeaderName::XCSRFToken));
        assert_eq!("X-Forwarded-For".try_into(), Ok(HeaderName::XForwardedFor));
        assert_eq!("x-forwarded-for".try_into(), Ok(HeaderName::XForwardedFor));
        assert_eq!("X-FORWARDED-FOR".try_into(), Ok(HeaderName::XForwardedFor));
        assert_eq!(
            "X-Forwarded-Host".try_into(),
            Ok(HeaderName::XForwardedHost)
        );
        assert_eq!(
            "x-forwarded-host".try_into(),
            Ok(HeaderName::XForwardedHost)
        );
        assert_eq!(
            "X-FORWARDED-HOST".try_into(),
            Ok(HeaderName::XForwardedHost)
        );
        assert_eq!("X-Real-Ip".try_into(), Ok(HeaderName::XReadIp));
        assert_eq!("x-real-ip".try_into(), Ok(HeaderName::XReadIp));
        assert_eq!("X-REAL-IP".try_into(), Ok(HeaderName::XReadIp));
        assert_eq!(
            "X-Hub-Signature-256".try_into(),
            Ok(HeaderName::XHubSignature256)
        );
        assert_eq!(
            "x-hub-signature-256".try_into(),
            Ok(HeaderName::XHubSignature256)
        );
        assert_eq!(
            "X-HUB-SIGNATURE-256".try_into(),
            Ok(HeaderName::XHubSignature256)
        );
        let unknown: Result<HeaderName> = "UNKNOWN".try_into();
        assert!(unknown.is_err());
    }

    #[test]
    fn as_ref() {
        assert_eq!(HeaderName::Accept.as_ref(), ACCEPT);
        assert_eq!(HeaderName::AcceptEncoding.as_ref(), ACCEPT_ENCODING);
        assert_eq!(HeaderName::AcceptLanguage.as_ref(), ACCEPT_LANGUAGE);
        assert_eq!(
            HeaderName::AccessControlRequestHeaders.as_ref(),
            ACCESS_CONTROL_REQUEST_HEADERS
        );
        assert_eq!(
            HeaderName::AccessControlRequestMethod.as_ref(),
            ACCESS_CONTROL_REQUEST_METHOD
        );
        assert_eq!(HeaderName::Authorization.as_ref(), AUTHORIZATION);
        assert_eq!(HeaderName::Connection.as_ref(), CONNECTION);
        assert_eq!(HeaderName::ContentEncoding.as_ref(), CONTENT_ENCODING);
        assert_eq!(HeaderName::ContentLength.as_ref(), CONTENT_LENGTH);
        assert_eq!(HeaderName::ContentType.as_ref(), CONTENT_TYPE);
        assert_eq!(HeaderName::Cookie.as_ref(), COOKIE);
        assert_eq!(HeaderName::Expect.as_ref(), EXPECT);
        assert_eq!(HeaderName::Host.as_ref(), HOST);
        assert_eq!(HeaderName::IfMatch.as_ref(), IF_MATCH);
        assert_eq!(HeaderName::IfModifiedSince.as_ref(), IF_MODIFIED_SINCE);
        assert_eq!(HeaderName::IfNoneMatch.as_ref(), IF_NONE_MATCH);
        assert_eq!(HeaderName::IfRange.as_ref(), IF_RANGE);
        assert_eq!(HeaderName::IfUnmodifiedSince.as_ref(), IF_UNMODIFIED_SINCE);
        assert_eq!(HeaderName::Origin.as_ref(), ORIGIN);
        assert_eq!(HeaderName::Range.as_ref(), RANGE);
        assert_eq!(HeaderName::TransferEncoding.as_ref(), TRANSFER_ENCODING);
        assert_eq!(HeaderName::UserAgent.as_ref(), USER_AGENT);
        assert_eq!(HeaderName::XCSRFToken.as_ref(), X_CSRF_TOKEN);
        assert_eq!(HeaderName::XForwardedFor.as_ref(), X_FORWARDED_FOR);
        assert_eq!(HeaderName::XForwardedHost.as_ref(), X_FORWARDED_HOST);
        assert_eq!(HeaderName::XReadIp.as_ref(), X_REAL_IP);
        assert_eq!(HeaderName::XHubSignature256.as_ref(), X_HUB_SIGNATURE_256);
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
