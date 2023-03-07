use thiserror::Error;

pub type Result<T> = std::result::Result<T, CpeError>;

#[derive(Error, Debug)]
pub enum CpeError {
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
    #[error("invalid character `{character}` at position {position} in component `{value}`")]
    InvalidComponent {
        value: String,
        position: usize,
        character: char,
    },
    #[error("Invalid CPE type \"{value}\"")]
    InvalidCpeType { value: String },
}
