use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use thiserror::Error as ThisError;

use nvd_model::error::DBError;

// API错误处理
pub type ApiResult<T> = Result<T, NVDApiError>;

// API错误枚举
#[derive(ThisError, Debug)]
pub enum NVDApiError {
  #[error("Not Found `{value}`")]
  NotFound { value: String },
  #[error("Internal Server Error `{value}`")]
  InternalServerError { value: String },
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

// 实现API错误转响应错误
impl ResponseError for NVDApiError {
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

impl From<DBError> for NVDApiError {
  fn from(err: DBError) -> Self {
    match err {
      DBError::DieselError { source } => match source.to_string().as_str() {
        "Record not found" => NVDApiError::NotFound {
          value: source.to_string(),
        },
        _ => {
          println!("{:?}", source.to_string());
          NVDApiError::InternalServerError {
            value: source.to_string(),
          }
        }
      },
      _ => NVDApiError::InternalServerError {
        value: err.to_string(),
      },
    }
  }
}
