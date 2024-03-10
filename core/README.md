## min_http11_core &nbsp;[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![crates.io Version](https://img.shields.io/crates/v/min_http11_core.svg)](https://crates.io/crates/min_http11_core) [![Documentation](https://docs.rs/min_http11_core/badge.svg)](https://docs.rs/min_http11_core)

```rust
pub enum Version {
    Http11,
    Unsupported(..),
}
```

```rust
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Other(..),
}
```

```rust
pub enum HeaderName {
    ContentLength,
    Host,
    IfMatch,
    IfNoneMatch,
...
Other(..),
Unknown(..),
}
```

```rust
pub struct KnownHeaders<'a> {
    pub content_length: Option<&'a [u8]>,
    pub host: Option<&'a [u8]>,
    pub if_match: Option<&'a [u8]>,
    pub if_none_match: Option<&'a [u8]>,
    ...
}
```
