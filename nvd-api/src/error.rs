use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use diesel::result::Error as DieselError;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, NVDApiError>;

#[derive(Error, Debug)]
pub enum NVDApiError {
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
  #[error("Not Found")]
  NotFound(),
  #[error("Internal Server Error")]
  InternalServerError,
}
impl From<DieselError> for NVDApiError {
  fn from(err: DieselError) -> Self {
    match err {
      DieselError::DatabaseError(kind, info) => {
        let message = info.details().unwrap_or_else(|| info.message()).to_string();
        NVDApiError::DatabaseErrorKind {
          value: format!("{kind:?}:{message}"),
        }
      }
      DieselError::NotFound => NVDApiError::NotFound,
      _ => NVDApiError::InternalServerError,
    }
  }
}
impl From<diesel::r2d2::PoolError> for NVDApiError {
  fn from(err: diesel::r2d2::PoolError) -> Self {
    match err {
      _ => NVDApiError::R2d2Error { source: err },
    }
  }
}

impl From<actix_web::error::BlockingError> for NVDApiError {
  fn from(err: actix_web::error::BlockingError) -> Self {
    match err {
      _ => NVDApiError::InternalServerError,
    }
  }
}
impl From<actix_web::Error> for NVDApiError {
  fn from(err: actix_web::Error) -> Self {
    match err {
      _ => NVDApiError::InternalServerError,
    }
  }
}

impl actix_web::error::ResponseError for NVDApiError {
  fn status_code(&self) -> StatusCode {
    match *self {
      NVDApiError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
      NVDApiError::NotFound => StatusCode::NOT_FOUND,
      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
  fn error_response(&self) -> HttpResponse {
    match self {
      NVDApiError::NotFound => HttpResponse::NotFound().json(msg),
      _ => HttpResponse::InternalServerError().json("Internal Server Error"),
    }
  }
}
