use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Unknown method {:?}", .0)]
    UnknownMethod(String),
    #[error("Unsupported version {:?}", .0)]
    UnsupportedVersion(String),
    #[error("Unknown header name {:?}", .0)]
    UnknownHeaderName(String),
    #[error("Custom header name is not lowercase {:?}", .0)]
    CustomHeaderNameNotLowercase(String),
}
