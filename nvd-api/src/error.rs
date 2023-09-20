use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use diesel::result::{Error as DieselError, Error};
use thiserror::Error;
// API错误处理
pub type ApiResult<T> = Result<T, NVDApiError>;
// 数据库错误处理
pub type DBResult<T> = Result<T, DBError>;
// API错误枚举
#[derive(Error, Debug)]
pub enum NVDApiError {
  #[error("Not Found `{value}`")]
  NotFound { value: String },
  #[error("Internal Server Error `{value}`")]
  InternalServerError { value: String },
}
// 数据库错误枚举
#[derive(Error, Debug)]
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

impl From<actix_web::error::BlockingError> for NVDApiError {
  fn from(err: actix_web::error::BlockingError) -> Self {
    NVDApiError::InternalServerError {
      value: err.to_string(),
    }
  }
}
impl From<actix_web::Error> for NVDApiError {
  fn from(err: actix_web::Error) -> Self {
    NVDApiError::InternalServerError {
      value: err.to_string(),
    }
  }
}

// 实现数据库错误转API错误
impl From<DBError> for NVDApiError {
  fn from(err: DBError) -> Self {
    match err {
      DBError::DieselError { source } => match source {
        Error::NotFound => NVDApiError::NotFound {
          value: source.to_string(),
        },
        _ => NVDApiError::InternalServerError {
          value: source.to_string(),
        },
      },
      _ => NVDApiError::InternalServerError {
        value: err.to_string(),
      },
    }
  }
}

// 实现API错误转响应错误
impl actix_web::error::ResponseError for NVDApiError {
  fn status_code(&self) -> StatusCode {
    match *self {
      NVDApiError::InternalServerError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
      NVDApiError::NotFound { .. } => StatusCode::NOT_FOUND,
    }
  }
  fn error_response(&self) -> HttpResponse {
    match self {
      NVDApiError::NotFound { value } => HttpResponse::NotFound().json(value),
      _ => HttpResponse::InternalServerError().json("Internal Server Error"),
    }
  }
}

// 实现数据库错误转响应错误
impl actix_web::error::ResponseError for DBError {
  fn status_code(&self) -> StatusCode {
    match self {
      DBError::DieselError { source } => match source {
        Error::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
      },
      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
  fn error_response(&self) -> HttpResponse {
    match self {
      DBError::DieselError { source } => match source {
        Error::NotFound => HttpResponse::NotFound().json(source.to_string()),
        _ => HttpResponse::InternalServerError().json("Internal Server Error"),
      },
      _ => HttpResponse::InternalServerError().json("Internal Server Error"),
    }
  }
}
