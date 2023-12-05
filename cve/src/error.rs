//! cve error
use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, CVEError>;

#[derive(ThisError, Debug, Clone)]
pub enum CVEError {
  #[error("error decoding value `{value}`, not well formed UTF-8")]
  Utf8Error {
    #[source]
    source: std::str::Utf8Error,
    value: String,
  },
  #[error("invalid prefix for `{value}`")]
  InvalidPrefix { value: String },
  #[error("Invalid CVE type `{value}`")]
  InvalidCveType { value: String },
  #[error("Invalid CVSS `{value}` at {scope}")]
  InvalidCVSS { value: String, scope: String },
  #[error("invalid cvss version `{value}` ({expected})")]
  InvalidCVSSVersion { value: String, expected: String },
}

impl From<&CVEError> for CVEError {
  fn from(value: &CVEError) -> Self {
    value.clone()
  }
}
