use thiserror::Error;

pub type Result<T> = std::result::Result<T, CVEError>;

#[derive(Error, Debug, Clone)]
pub enum CVEError {
  #[error("error decoding value `{value}`, not well formed UTF-8")]
  Utf8Error {
    #[source]
    source: std::str::Utf8Error,
    value: String,
  },
  #[error("invalid prefix for `{value}`")]
  InvalidPrefix { value: String },
  #[error("Invalid CVE type \"{value}\"")]
  InvalidCveType { value: String },
  #[error("Invalid CVSS \"{value}\"")]
  InvalidCVSS { value: String },
  #[error("invalid cvss version `{value}` ({expected})")]
  InvalidCVSSVersion { value: String, expected: String },
}

impl From<&CVEError> for CVEError {
  fn from(value: &CVEError) -> Self {
    return value.clone();
  }
}
