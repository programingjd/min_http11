use std::io;
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
    #[error("Invalid header name {:?}", .0)]
    InvalidHeaderName(String),
    #[error("Bad request")]
    BadRequest,
    #[error("transparent")]
    ReadError(#[from] IoError),
    #[error("Unexpected eof")]
    UnexpectedEndOfFile,
    #[error("Request too large")]
    RequestTooLarge,
    #[error("Read timeout")]
    ReadTimeout,
    #[error("Unsupported transfer-encoding")]
    UnsupportedTransferEncoding,
}

#[derive(Error, Debug)]
#[error("transparent")]
pub struct IoError(#[from] io::Error);

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::ReadError(IoError(value))
    }
}
