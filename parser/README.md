## min_http11_parser &nbsp;[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![crates.io Version](https://img.shields.io/crates/v/min_http11_parser.svg)](https://crates.io/crates/min_http11_parser) [![Documentation](https://docs.rs/min_http11_parser/badge.svg)](https://docs.rs/min_http11_parser)

```rust
let mut reader = BufReader::new(reader);
let mut buffer = vec![];
let (method, path, known_headers, _other_headers) = Parser::default ()
.parse_request_line_and_headers( & mut reader, & mut buffer)
.await?;
```
