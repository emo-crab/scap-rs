use diesel::result::Error as DieselError;
use thiserror::Error as ThisError;
pub type DBResult<T> = Result<T, DBError>;
// 数据库错误枚举
#[derive(ThisError, Debug)]
pub enum DBError {
  #[error("DieselError `{source}`")]
  DieselError {
    #[source]
    source: DieselError,
  },
  #[error("Diesel r2d2 PoolError `{source}`")]
  R2d2Error {
    #[source]
    source: diesel::r2d2::PoolError,
  },
  #[error("DatabaseErrorKind `{value}`")]
  DatabaseErrorKind { value: String },
}

impl From<DieselError> for DBError {
  fn from(err: DieselError) -> Self {
    match err {
      DieselError::DatabaseError(kind, info) => {
        let message = info.details().unwrap_or_else(|| info.message()).to_string();
        DBError::DatabaseErrorKind {
          value: format!("{kind:?}:{message}"),
        }
      }
      DieselError::NotFound => DBError::DieselError { source: err },
      _ => DBError::DieselError { source: err },
    }
  }
}
impl From<diesel::r2d2::PoolError> for DBError {
  fn from(err: diesel::r2d2::PoolError) -> Self {
    DBError::R2d2Error { source: err }
  }
}
