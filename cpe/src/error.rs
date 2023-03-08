use thiserror::Error;

pub type Result<T> = std::result::Result<T, CpeError>;

#[derive(Error, Debug)]
pub enum CpeError {
    #[error("invalid wfn `{value}`")]
    InvalidWfn { value: String },
    #[error("invalid uri `{value}`")]
    InvalidUri { value: String },
    #[error("invalid part component `{value}`")]
    InvalidPart { value: String },
    #[error("error decoding value `{value}`, not well formed UTF-8")]
    Utf8Error {
        #[source]
        source: std::str::Utf8Error,
        value: String,
    },
    #[error("invalid prefix for `{value}`")]
    InvalidPrefix { value: String },
    #[error("Invalid CPE type \"{value}\"")]
    InvalidCpeType { value: String },
}
