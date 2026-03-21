use memchr::{memchr, memchr_iter};
use min_http11_core::error::{Error, Result};
use min_http11_core::hash::hash;
use min_http11_core::method::Method;

use min_http11_core::request::{
    HeaderName, KnownHeaders, CONTENT_LENGTH, CONTENT_LENGTH_HASH, HOST, HOST_HASH, IF_MATCH,
    IF_MATCH_HASH, IF_NONE_MATCH, IF_NONE_MATCH_HASH, TRANSFER_ENCODING, TRANSFER_ENCODING_HASH,
    X_HUB_SIGNATURE_256, X_HUB_SIGNATURE_256_HASH,
};
#[cfg(not(feature = "_minimal"))]
use min_http11_core::request::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_ENCODING_HASH, ACCEPT_HASH, ACCEPT_LANGUAGE,
    ACCEPT_LANGUAGE_HASH, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_HEADERS_HASH,
    ACCESS_CONTROL_REQUEST_METHOD, ACCESS_CONTROL_REQUEST_METHOD_HASH, AUTHORIZATION,
    AUTHORIZATION_HASH, CONNECTION, CONNECTION_HASH, CONTENT_ENCODING, CONTENT_ENCODING_HASH,
    CONTENT_TYPE, CONTENT_TYPE_HASH, COOKIE, COOKIE_HASH, EXPECT, EXPECT_HASH, IF_MODIFIED_SINCE,
    IF_MODIFIED_SINCE_HASH, IF_RANGE, IF_RANGE_HASH, IF_UNMODIFIED_SINCE, IF_UNMODIFIED_SINCE_HASH,
    ORIGIN, ORIGIN_HASH, RANGE, RANGE_HASH, USER_AGENT, USER_AGENT_HASH, X_CSRF_TOKEN,
    X_CSRF_TOKEN_HASH, X_FORWARDED_FOR, X_FORWARDED_FOR_HASH, X_FORWARDED_HOST,
    X_FORWARDED_HOST_HASH, X_REAL_IP, X_REAL_IP_HASH,
};
use min_http11_core::util::AsciiLowercaseTestExt;
use min_http11_core::version::Version;
use read_until_slice::AsyncBufReadUntilSliceExt;
use std::collections::BTreeMap;
use std::str::from_utf8;
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
    body_read_timeout: Duration,
    request_line_max_size: u64,
    headers_max_size: u64,
    body_max_size: u64,
    other_headers: Option<BTreeMap<u32, &'static [u8]>>,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            request_line_read_timeout: Duration::from_millis(200_u64),
            headers_read_timeout: Duration::from_millis(200_u64),
            body_read_timeout: Duration::from_millis(10_000_u64),
            request_line_max_size: 4_096_u64,
            headers_max_size: 16_384_u64,
            body_max_size: 65_536_u64,
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
const SEMI_COLON: u8 = b';';
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = b"\r\n";

impl Parser {
    pub async fn parse_request_line<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
    ) -> Result<(Method, &'c [u8])> {
        timeout(self.request_line_read_timeout, async {
            let mut reader = reader.take(self.request_line_max_size);
            let n = reader.read_until_slice(CRLF, buffer).await.map_err(|err| {
                if reader.limit() == 0 {
                    Error::RequestTooLarge
                } else {
                    err.into()
                }
            })?;
            if n == 0 {
                return Err(if reader.limit() == 0 {
                    Error::RequestTooLarge
                } else {
                    Error::UnexpectedEndOfFile
                });
            }
            let request_line = buffer[buffer.len() - n..]
                .strip_suffix(CRLF)
                .ok_or_else(|| {
                    if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    }
                })?;
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
        .await
        .map_err(|_| Error::ReadTimeout)?
    }

    pub async fn parse_headers<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
    ) -> Result<(KnownHeaders<'a>, Option<BTreeMap<&'static [u8], &'a [u8]>>)> {
        timeout(self.headers_read_timeout, async {
            let mut reader = reader.take(self.headers_max_size);
            let start = buffer.len();
            loop {
                let n = reader.read_until_slice(CRLF, buffer).await.map_err(|err| {
                    if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        err.into()
                    }
                })?;
                if n == 0 {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                if !buffer.ends_with(CRLF) {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                if n == 2 {
                    break;
                }
            }
            let buffer = &buffer[start..buffer.len() - 2];
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
                            return Err(if reader.limit() == 0 {
                                Error::RequestTooLarge
                            } else {
                                Error::UnexpectedEndOfFile
                            });
                        }
                    };
                    let line = &buffer[i..j];
                    i = j + 2;
                    let mut iter = memchr_iter(COLON, line);
                    let i = iter.next().ok_or(Error::BadRequest)?;
                    if i == 0 {
                        return Err(Error::BadRequest);
                    }
                    let key = &line[..i];
                    if key.is_empty()
                        || key[0].is_ascii_whitespace()
                        || key[key.len() - 1].is_ascii_whitespace()
                    {
                        return Err(Error::BadRequest);
                    }
                    let value = &line[i + 1..].trim_ascii();
                    debug!("{}: {}", key.escape_ascii(), value.escape_ascii());
                    if key.is_ascii_lowercase() {
                        let h = hash(key);
                        let res = _with_known_header(known_headers, h, key, value)?;
                        known_headers = res.0;
                        if res.1 {
                            custom_headers = _with_other_header(
                                custom_headers,
                                self.other_headers.as_ref(),
                                h,
                                key,
                                value,
                            );
                        }
                    } else {
                        let key = key.to_ascii_lowercase();
                        let h = hash(&key);
                        let res = _with_known_header(known_headers, h, &key, value)?;
                        known_headers = res.0;
                        if res.1 {
                            custom_headers = _with_other_header(
                                custom_headers,
                                self.other_headers.as_ref(),
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
        .await
        .map_err(|_| Error::ReadTimeout)?
    }

    pub async fn parse_body<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
        headers: &'a KnownHeaders<'a>,
    ) -> Result<&'c [u8]> {
        match headers.transfer_encoding.map(|it| it.trim_ascii()).as_ref() {
            Some(value) if value.eq_ignore_ascii_case(b"chunked") => {
                return self.parse_chunked_body(reader, buffer).await;
            }
            Some(value) if value.eq_ignore_ascii_case(b"identity") => {}
            Some(_) => {
                return Err(Error::UnsupportedTransferEncoding);
            }
            None => {}
        };
        if let Some(content_length) = headers
            .content_length
            .and_then(|it| from_utf8(it).ok())
            .and_then(|it| it.parse::<u64>().ok())
        {
            if content_length > self.body_max_size {
                Err(Error::RequestTooLarge)
            } else {
                let body = timeout(self.body_read_timeout, async {
                    let mut reader = reader.take(content_length);
                    let n = reader.read_to_end(buffer).await?;
                    if (n as u64) < content_length {
                        return Err(if reader.limit() == 0 {
                            Error::RequestTooLarge
                        } else {
                            Error::UnexpectedEndOfFile
                        });
                    }
                    Ok(&buffer[buffer.len() - n..])
                })
                .await
                .map_err(|_| Error::ReadTimeout)?;
                Ok(body?)
            }
        } else {
            Err(Error::BadRequest)
        }
    }

    async fn parse_chunked_body<'a, 'b, 'c: 'a>(
        &'a self,
        reader: &'b mut (impl AsyncBufRead + Unpin),
        buffer: &'c mut Vec<u8>,
    ) -> Result<&'c [u8]> {
        timeout(self.body_read_timeout, async {
            let mut reader = reader.take(self.body_max_size);
            let start = buffer.len();
            let mut discarded = 0;
            loop {
                let n = reader.read_until_slice(CRLF, buffer).await.map_err(|err| {
                    if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        err.into()
                    }
                })?;
                if n == 0 {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                if !buffer.ends_with(CRLF) {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                let chunk_size_line = &buffer[buffer.len() - n..buffer.len() - 2];
                let end = memchr(SEMI_COLON, chunk_size_line).unwrap_or(chunk_size_line.len());
                let chunk_size = from_utf8(chunk_size_line[..end].trim_ascii())
                    .ok()
                    .and_then(|it| u64::from_str_radix(it, 16).ok())
                    .ok_or(Error::BadRequest)?;
                if chunk_size == 0 {
                    buffer.truncate(buffer.len() - n);
                    break;
                }
                if (buffer.len() - start + discarded) as u64 + chunk_size > self.body_max_size {
                    return Err(Error::RequestTooLarge);
                }
                discarded += n;
                buffer.truncate(buffer.len() - n);
                {
                    let mut reader = (&mut reader).take(chunk_size);
                    let n = reader.read_to_end(buffer).await?;
                    if (n as u64) < chunk_size {
                        return Err(if reader.limit() == 0 {
                            Error::RequestTooLarge
                        } else {
                            Error::UnexpectedEndOfFile
                        });
                    }
                }
                if reader.read_u8().await.map_err(|err| {
                    if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        err.into()
                    }
                })? != CR
                    || reader.read_u8().await.map_err(|err| {
                        if reader.limit() == 0 {
                            Error::RequestTooLarge
                        } else {
                            err.into()
                        }
                    })? != LF
                {
                    return Err(Error::BadRequest);
                }
                discarded += 2;
            }
            loop {
                let n = reader.read_until_slice(CRLF, buffer).await.map_err(|err| {
                    if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        err.into()
                    }
                })?;
                if n == 0 {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                if !buffer.ends_with(CRLF) {
                    return Err(if reader.limit() == 0 {
                        Error::RequestTooLarge
                    } else {
                        Error::UnexpectedEndOfFile
                    });
                }
                buffer.truncate(buffer.len() - n);
                if n == 2 {
                    break;
                }
            }
            Ok(&buffer[start..])
        })
        .await
        .map_err(|_| Error::ReadTimeout)?
    }
}

fn _with_known_header<'a>(
    mut known_headers: KnownHeaders<'a>,
    hash: u32,
    lowercase_key: &[u8],
    value: &'a [u8],
) -> Result<(KnownHeaders<'a>, bool)> {
    macro_rules! set_once {
        ($field:ident) => {
            if known_headers.$field.is_some() {
                return Err(Error::BadRequest);
            }
            known_headers.$field = Some(value);
        };
    }
    #[cfg(feature = "_minimal")]
    match hash {
        CONTENT_LENGTH_HASH if lowercase_key == CONTENT_LENGTH => {
            if known_headers.transfer_encoding.is_some() {
                return Err(Error::BadRequest);
            }
            set_once!(content_length);
        }
        HOST_HASH if lowercase_key == HOST => {
            set_once!(host);
        }
        TRANSFER_ENCODING_HASH if lowercase_key == TRANSFER_ENCODING => {
            if known_headers.content_length.is_some() {
                return Err(Error::BadRequest);
            }
            set_once!(transfer_encoding);
        }
        IF_MATCH_HASH if lowercase_key == IF_MATCH => {
            set_once!(if_match);
        }
        IF_NONE_MATCH_HASH if lowercase_key == IF_NONE_MATCH => {
            set_once!(if_none_match);
        }
        X_HUB_SIGNATURE_256_HASH if lowercase_key == X_HUB_SIGNATURE_256 => {
            set_once!(x_hub_signature_256_hash);
        }
        _ => return Ok((known_headers, true)),
    }
    #[cfg(not(feature = "_minimal"))]
    match hash {
        ACCEPT_HASH if lowercase_key == ACCEPT => {
            set_once!(accept);
        }
        ACCEPT_ENCODING_HASH if lowercase_key == ACCEPT_ENCODING => {
            set_once!(accept_encoding);
        }
        ACCEPT_LANGUAGE_HASH if lowercase_key == ACCEPT_LANGUAGE => {
            set_once!(accept_language);
        }
        ACCESS_CONTROL_REQUEST_HEADERS_HASH if lowercase_key == ACCESS_CONTROL_REQUEST_HEADERS => {
            set_once!(access_control_request_headers);
        }
        ACCESS_CONTROL_REQUEST_METHOD_HASH if lowercase_key == ACCESS_CONTROL_REQUEST_METHOD => {
            set_once!(access_control_request_method);
        }
        AUTHORIZATION_HASH if lowercase_key == AUTHORIZATION => {
            set_once!(authorization);
        }
        CONNECTION_HASH if lowercase_key == CONNECTION => {
            set_once!(connection);
        }
        CONTENT_ENCODING_HASH if lowercase_key == CONTENT_ENCODING => {
            set_once!(content_encoding);
        }
        CONTENT_LENGTH_HASH if lowercase_key == CONTENT_LENGTH => {
            if known_headers.transfer_encoding.is_some() {
                return Err(Error::BadRequest);
            }
            set_once!(content_length);
        }
        CONTENT_TYPE_HASH if lowercase_key == CONTENT_TYPE => {
            set_once!(content_type);
        }
        COOKIE_HASH if lowercase_key == COOKIE => {
            set_once!(cookie);
        }
        EXPECT_HASH if lowercase_key == EXPECT => {
            set_once!(expect);
        }
        HOST_HASH if lowercase_key == HOST => {
            set_once!(host);
        }
        IF_MATCH_HASH if lowercase_key == IF_MATCH => {
            set_once!(if_match);
        }
        IF_MODIFIED_SINCE_HASH if lowercase_key == IF_MODIFIED_SINCE => {
            set_once!(if_modified_since);
        }
        IF_NONE_MATCH_HASH if lowercase_key == IF_NONE_MATCH => {
            set_once!(if_none_match);
        }
        IF_RANGE_HASH if lowercase_key == IF_RANGE => {
            set_once!(if_range);
        }
        IF_UNMODIFIED_SINCE_HASH if lowercase_key == IF_UNMODIFIED_SINCE => {
            set_once!(if_unmodified_since);
        }
        ORIGIN_HASH if lowercase_key == ORIGIN => {
            set_once!(origin);
        }
        RANGE_HASH if lowercase_key == RANGE => {
            set_once!(range);
        }
        TRANSFER_ENCODING_HASH if lowercase_key == TRANSFER_ENCODING => {
            if known_headers.content_length.is_some() {
                return Err(Error::BadRequest);
            }
            set_once!(transfer_encoding);
        }
        USER_AGENT_HASH if lowercase_key == USER_AGENT => {
            set_once!(user_agent);
        }
        X_CSRF_TOKEN_HASH if lowercase_key == X_CSRF_TOKEN => {
            set_once!(x_csrf_token);
        }
        X_FORWARDED_FOR_HASH if lowercase_key == X_FORWARDED_FOR => {
            set_once!(x_forwarded_for);
        }
        X_FORWARDED_HOST_HASH if lowercase_key == X_FORWARDED_HOST => {
            set_once!(x_forwarded_host);
        }
        X_REAL_IP_HASH if lowercase_key == X_REAL_IP => {
            set_once!(x_real_ip);
        }
        X_HUB_SIGNATURE_256_HASH if lowercase_key == X_HUB_SIGNATURE_256 => {
            set_once!(x_hub_signature_256_hash);
        }
        _ => return Ok((known_headers, true)),
    }
    Ok((known_headers, false))
}

fn _with_other_header<'a>(
    custom_headers: Option<BTreeMap<&'static [u8], &'a [u8]>>,
    other_headers: Option<&BTreeMap<u32, &'static [u8]>>,
    hash: u32,
    lowercase_key: &[u8],
    value: &'a [u8],
) -> Option<BTreeMap<&'static [u8], &'a [u8]>> {
    if let Some(other_headers) = other_headers
        && let Some(&found) = other_headers.get(&hash)
        && found == lowercase_key
    {
        let mut custom_headers = custom_headers.unwrap_or_default();
        custom_headers.insert(found, value);
        return Some(custom_headers);
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
            Host: fake.xyz\r\n\
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
        assert!(
            parser
                .parse_headers(&mut reader, &mut buffer)
                .await
                .is_err()
        );
        let bytes = b"\
            GET /test HTTP/1.1\r\n\
            Content-Length: 100\r\n\
            Transfer-Encoding: chunked\r\n\
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
        assert!(
            parser
                .parse_headers(&mut reader, &mut buffer)
                .await
                .is_err()
        );
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
