//! nvd-db error
use diesel::result::Error as DieselError;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, NVDDBError>;

#[derive(Error, Debug)]
pub enum NVDDBError {
  #[error("DieselError")]
  DieselError {
    #[source]
    source: DieselError,
  },
  #[error("DatabaseErrorKind `{value}`")]
  DatabaseErrorKind { value: String },
}
impl From<DieselError> for NVDDBError {
  fn from(err: DieselError) -> Self {
    match err {
      DieselError::DatabaseError(kind, info) => {
        let message = info.details().unwrap_or_else(|| info.message()).to_string();
        NVDDBError::DatabaseErrorKind {
          value: format!("{:?}:{}", kind, message),
        }
      }
      _ => NVDDBError::DieselError { source: err },
    }
  }
}
