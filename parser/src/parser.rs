use memchr::memchr_iter;
use min_http11_core::error::{Error, Result};
use min_http11_core::hash::hash;
use min_http11_core::method::Method;

use min_http11_core::request::{
    HeaderName, KnownHeaders, CONTENT_LENGTH, CONTENT_LENGTH_HASH, HOST, HOST_HASH, IF_MATCH,
    IF_MATCH_HASH, IF_NONE_MATCH, IF_NONE_MATCH_HASH, X_HUB_SIGNATURE_256,
    X_HUB_SIGNATURE_256_HASH,
};
#[cfg(not(feature = "_minimal"))]
use min_http11_core::request::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_ENCODING_HASH, ACCEPT_HASH, ACCEPT_LANGUAGE,
    ACCEPT_LANGUAGE_HASH, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_HEADERS_HASH,
    ACCESS_CONTROL_REQUEST_METHOD, ACCESS_CONTROL_REQUEST_METHOD_HASH, AUTHORIZATION,
    AUTHORIZATION_HASH, CONNECTION, CONNECTION_HASH, CONTENT_ENCODING, CONTENT_ENCODING_HASH,
    CONTENT_TYPE, CONTENT_TYPE_HASH, COOKIE, COOKIE_HASH, EXPECT, EXPECT_HASH, IF_MODIFIED_SINCE,
    IF_MODIFIED_SINCE_HASH, IF_RANGE, IF_RANGE_HASH, IF_UNMODIFIED_SINCE, IF_UNMODIFIED_SINCE_HASH,
    ORIGIN, ORIGIN_HASH, RANGE, RANGE_HASH, TRANSFER_ENCODING, TRANSFER_ENCODING_HASH, USER_AGENT,
    USER_AGENT_HASH, X_CSRF_TOKEN, X_CSRF_TOKEN_HASH, X_FORWARDED_FOR, X_FORWARDED_FOR_HASH,
    X_FORWARDED_HOST, X_FORWARDED_HOST_HASH, X_REAL_IP, X_REAL_IP_HASH,
};
use min_http11_core::util::AsciiLowercaseTestExt;
use min_http11_core::version::Version;
use read_until_slice::AsyncBufReadUntilSliceExt;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncReadExt};
use tokio::time::timeout;
use tracing::debug;

pub struct Request<'a> {
    pub method: Method,
    pub path: &'a [u8],
    pub known_headers: KnownHeaders<'a>,
    pub custom_headers: Option<BTreeMap<&'static [u8], &'a [u8]>>,
    pub body: Option<&'a [u8]>,
}

pub struct Parser {
    request_line_read_timeout: Duration,
    headers_read_timeout: Duration,
    request_line_max_size: u64,
    headers_max_size: u64,
    other_headers: Option<BTreeMap<u32, &'static [u8]>>,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            request_line_read_timeout: Duration::from_millis(200_u64),
            headers_read_timeout: Duration::from_millis(200_u64),
            request_line_max_size: 4_096_u64,
            headers_max_size: 16_384_u64,
            other_headers: None,
        }
    }
}

impl Parser {
    pub fn with_header(self, header_name: &'static [u8]) -> Result<Self> {
        let header_name = HeaderName::try_from_static(header_name)?;
        Ok(match header_name {
            HeaderName::Other(key) => {
                let mut custom_headers = self.other_headers.unwrap_or_default();
                custom_headers.insert(hash(key), key);
                Parser {
                    other_headers: Some(custom_headers),
                    ..self
                }
            }
            _ => self,
        })
    }
    pub fn with_request_line_read_timeout(self, timeout: Duration) -> Self {
        Parser {
            request_line_read_timeout: timeout,
            ..self
        }
    }
    pub fn with_headers_read_timeout(self, timeout: Duration) -> Self {
        Parser {
            headers_read_timeout: timeout,
            ..self
        }
    }
    pub fn with_request_line_max_size(self, size: u16) -> Self {
        Parser {
            request_line_max_size: size as u64,
            ..self
        }
    }
    pub fn with_headers_max_size(self, size: u16) -> Self {
        Parser {
            headers_max_size: size as u64,
            ..self
        }
    }
}

const SPACE: u8 = b' ';
const COLON: u8 = b':';
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = b"\r\n";
const CRLF_CRLF: &[u8] = b"\r\n\r\n";

impl Parser {
    pub async fn parse_request_line<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
    ) -> Result<(Method, &'c [u8])> {
        let request_line = timeout(self.request_line_read_timeout, async {
            let mut reader = reader.take(self.request_line_max_size);
            let n = reader.read_until_slice(CRLF, buffer).await?;
            if n == 0 {
                return Err(Error::UnexpectedEndOfFile);
            }
            let buffer = &buffer[buffer.len() - n..];
            if !buffer.ends_with(CRLF) {
                return Err(Error::UnexpectedEndOfFile);
            }
            let request_line = &buffer[..buffer.len() - 2];
            debug!("{}", request_line.escape_ascii());
            let mut iter = memchr_iter(SPACE, request_line);
            let first = iter.next().ok_or(Error::BadRequest)?;
            let second = iter.next().ok_or(Error::BadRequest)?;
            if iter.next().is_some() {
                return Err(Error::BadRequest);
            }
            let method = Method::try_from(&request_line[0..first])?;
            let path = &request_line[first + 1..second];
            let _ = Version::try_from(&request_line[second + 1..])?;
            Ok((method, path))
        })
        .await;
        let request_line = match request_line {
            Err(_) => Err(Error::ReadTimeout)?,
            Ok(result) => result?,
        };
        Ok(request_line)
    }

    pub async fn parse_headers<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
    ) -> Result<(KnownHeaders<'a>, Option<BTreeMap<&'static [u8], &'a [u8]>>)> {
        let headers = timeout(self.headers_read_timeout, async {
            let mut reader = reader.take(self.headers_max_size);
            let n = reader.read_until_slice(CRLF_CRLF, buffer).await?;
            if n == 0 {
                return Err(Error::UnexpectedEndOfFile);
            }
            let buffer = &buffer[buffer.len() - n..];
            if !buffer.ends_with(CRLF_CRLF) {
                return Err(Error::UnexpectedEndOfFile);
            }
            let buffer = &buffer[..buffer.len() - 2];
            let mut known_headers = KnownHeaders::default();
            let mut custom_headers = None;
            if !buffer.is_empty() {
                let mut iter = memchr_iter(CR, buffer);
                let mut i = 0;
                while i < buffer.len() {
                    let j = loop {
                        if let Some(i) = iter.next() {
                            if i + 1 < buffer.len() && buffer[i + 1] == LF {
                                break i;
                            }
                        } else {
                            return Err(Error::UnexpectedEndOfFile);
                        }
                    };
                    let line = &buffer[i..j];
                    i = j + 2;
                    let mut iter = memchr_iter(SPACE, line);
                    let first = iter.next().ok_or(Error::BadRequest)?;
                    if first == 0 || line[first - 1] != COLON {
                        return Err(Error::BadRequest);
                    }
                    let key = &line[..first - 1];
                    let value = &line[first + 1..];
                    debug!("{}: {}", key.escape_ascii(), value.escape_ascii());
                    if key.is_ascii_lowercase() {
                        let h = hash(key);
                        let res = _with_known_header(known_headers, h, key, value);
                        known_headers = res.0;
                        if res.1 {
                            custom_headers = _with_other_header(
                                custom_headers,
                                &self.other_headers,
                                h,
                                key,
                                value,
                            );
                        }
                    } else {
                        let key = key.to_ascii_lowercase();
                        let h = hash(&key);
                        let res = _with_known_header(known_headers, hash(&key), &key, value);
                        known_headers = res.0;
                        if res.1 {
                            custom_headers = _with_other_header(
                                custom_headers,
                                &self.other_headers,
                                h,
                                &key,
                                value,
                            );
                        }
                    };
                }
            }
            Ok((known_headers, custom_headers))
        })
        .await;
        let request_line = match headers {
            Err(_) => Err(Error::ReadTimeout)?,
            Ok(result) => result?,
        };
        Ok(request_line)
    }
}

fn _with_known_header<'a>(
    mut known_headers: KnownHeaders<'a>,
    hash: u32,
    lowercase_key: &[u8],
    value: &'a [u8],
) -> (KnownHeaders<'a>, bool) {
    #[cfg(feature = "_minimal")]
    match hash {
        CONTENT_LENGTH_HASH if lowercase_key == CONTENT_LENGTH => {
            known_headers.content_length = Some(value);
        }
        HOST_HASH if lowercase_key == HOST => {
            known_headers.host = Some(value);
        }
        IF_MATCH_HASH if lowercase_key == IF_MATCH => {
            known_headers.if_match = Some(value);
        }
        IF_NONE_MATCH_HASH if lowercase_key == IF_NONE_MATCH => {
            known_headers.if_none_match = Some(value);
        }
        X_HUB_SIGNATURE_256_HASH if lowercase_key == X_HUB_SIGNATURE_256 => {
            known_headers.x_hub_signature_256_hash = Some(value);
        }
        _ => return (known_headers, true),
    }
    #[cfg(not(feature = "_minimal"))]
    match hash {
        ACCEPT_HASH if lowercase_key == ACCEPT => {
            known_headers.accept = Some(value);
        }
        ACCEPT_ENCODING_HASH if lowercase_key == ACCEPT_ENCODING => {
            known_headers.accept_encoding = Some(value);
        }
        ACCEPT_LANGUAGE_HASH if lowercase_key == ACCEPT_LANGUAGE => {
            known_headers.accept_language = Some(value);
        }
        ACCESS_CONTROL_REQUEST_HEADERS_HASH if lowercase_key == ACCESS_CONTROL_REQUEST_HEADERS => {
            known_headers.access_control_request_headers = Some(value);
        }
        ACCESS_CONTROL_REQUEST_METHOD_HASH if lowercase_key == ACCESS_CONTROL_REQUEST_METHOD => {
            known_headers.access_control_request_method = Some(value);
        }
        AUTHORIZATION_HASH if lowercase_key == AUTHORIZATION => {
            known_headers.authorization = Some(value);
        }
        CONNECTION_HASH if lowercase_key == CONNECTION => {
            known_headers.connection = Some(value);
        }
        CONTENT_ENCODING_HASH if lowercase_key == CONTENT_ENCODING => {
            known_headers.content_encoding = Some(value);
        }
        CONTENT_LENGTH_HASH if lowercase_key == CONTENT_LENGTH => {
            known_headers.content_length = Some(value);
        }
        CONTENT_TYPE_HASH if lowercase_key == CONTENT_TYPE => {
            known_headers.content_type = Some(value);
        }
        COOKIE_HASH if lowercase_key == COOKIE => {
            known_headers.cookie = Some(value);
        }
        EXPECT_HASH if lowercase_key == EXPECT => {
            known_headers.expect = Some(value);
        }
        HOST_HASH if lowercase_key == HOST => {
            known_headers.host = Some(value);
        }
        IF_MATCH_HASH if lowercase_key == IF_MATCH => {
            known_headers.if_match = Some(value);
        }
        IF_MODIFIED_SINCE_HASH if lowercase_key == IF_MODIFIED_SINCE => {
            known_headers.if_modified_since = Some(value);
        }
        IF_NONE_MATCH_HASH if lowercase_key == IF_NONE_MATCH => {
            known_headers.if_none_match = Some(value);
        }
        IF_RANGE_HASH if lowercase_key == IF_RANGE => {
            known_headers.if_range = Some(value);
        }
        IF_UNMODIFIED_SINCE_HASH if lowercase_key == IF_UNMODIFIED_SINCE => {
            known_headers.if_unmodified_since = Some(value);
        }
        ORIGIN_HASH if lowercase_key == ORIGIN => {
            known_headers.origin = Some(value);
        }
        RANGE_HASH if lowercase_key == RANGE => {
            known_headers.range = Some(value);
        }
        TRANSFER_ENCODING_HASH if lowercase_key == TRANSFER_ENCODING => {
            known_headers.transfer_encoding = Some(value);
        }
        USER_AGENT_HASH if lowercase_key == USER_AGENT => {
            known_headers.user_agent = Some(value);
        }
        X_CSRF_TOKEN_HASH if lowercase_key == X_CSRF_TOKEN => {
            known_headers.x_csrf_token = Some(value);
        }
        X_FORWARDED_FOR_HASH if lowercase_key == X_FORWARDED_FOR => {
            known_headers.x_forwarded_for = Some(value);
        }
        X_FORWARDED_HOST_HASH if lowercase_key == X_FORWARDED_HOST => {
            known_headers.x_forwarded_host = Some(value);
        }
        X_REAL_IP_HASH if lowercase_key == X_REAL_IP => {
            known_headers.x_read_ip = Some(value);
        }
        X_HUB_SIGNATURE_256_HASH if lowercase_key == X_HUB_SIGNATURE_256 => {
            known_headers.x_hub_signature_256_hash = Some(value);
        }
        _ => return (known_headers, true),
    }
    (known_headers, false)
}

fn _with_other_header<'a>(
    custom_headers: Option<BTreeMap<&'static [u8], &'a [u8]>>,
    other_headers: &Option<BTreeMap<u32, &'static [u8]>>,
    hash: u32,
    lowercase_key: &[u8],
    value: &'a [u8],
) -> Option<BTreeMap<&'static [u8], &'a [u8]>> {
    if let Some(other_headers) = other_headers {
        if let Some(&found) = other_headers.get(&hash) {
            if found == lowercase_key {
                let mut custom_headers = custom_headers.unwrap_or_default();
                custom_headers.insert(found, value);
                return Some(custom_headers);
            }
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;
    use tracing::Level;

    #[tokio::test(flavor = "current_thread")]
    async fn parse_request_line_and_headers() {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_ansi(true)
            .compact()
            .init();
        let parser = Parser::default();
        let bytes = b"\
            GET /test HTTP/1.1\r\n\
            \r\n\
        ";
        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        let mut buffer = vec![];
        let (method, path) = parser
            .parse_request_line(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(method, Method::Get);
        assert_eq!(&path, b"/test");
        let bytes = b"\
            HEAD / HTTP/1.1\r\n\
            Host: example.org\r\n\
            \r\n\
        ";
        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        let (method, path) = parser
            .parse_request_line(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(method, Method::Head);
        assert_eq!(&path, b"/");
        let (known_headers, _) = parser
            .parse_headers(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(known_headers.host, Some(b"example.org".as_slice()));
        let bytes = b"\
            POST /post HTTP/1.1\r\n\
            Host: example.org\r\n\
            content-type: application/json\r\n\
            content-length: 0\r\n\
            \r\n\
        ";
        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        let mut buffer = vec![];
        let (method, path) = parser
            .parse_request_line(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(method, Method::Post);
        assert_eq!(&path, b"/post");
        let (known_headers, _) = parser
            .parse_headers(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(known_headers.host, Some(b"example.org".as_slice()));
        #[cfg(not(feature = "_minimal"))]
        assert_eq!(
            known_headers.content_type,
            Some(b"application/json".as_slice())
        );
        assert_eq!(known_headers.content_length, Some(b"0".as_slice()));
        let bytes = b"\
            GET /test HTTP/1.1\r\n\
            Host: example.org\r\n\
            x-test: 1\r\n\
            \r\n\
        ";
        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        let mut buffer = vec![];
        let parser = parser.with_header(b"x-test").unwrap();
        let (method, path) = parser
            .parse_request_line(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(method, Method::Get);
        assert_eq!(&path, b"/test");
        let (known_headers, custom_headers) = parser
            .parse_headers(&mut reader, &mut buffer)
            .await
            .unwrap();
        assert_eq!(known_headers.host, Some(b"example.org".as_slice()));
        assert!(custom_headers.is_some());
        let custom_headers = custom_headers.unwrap();
        assert_eq!(
            custom_headers.get(b"x-test".as_slice()),
            Some(&b"1".as_slice())
        );
    }
}
