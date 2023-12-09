//! nvd api error
use crate::pagination::Object;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::num::NonZeroU16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("Invalid NVD API Token: {}", source)]
  InvalidApiToken {
    source: reqwest::header::InvalidHeaderValue,
  },

  #[error("Unable to build reqwest HTTP client: {}", source)]
  BuildingClient { source: reqwest::Error },

  #[error("Error sending HTTP request: {}", source)]
  RequestFailed {
    #[from]
    source: reqwest::Error,
  },

  #[error("Error reading response: {}", source)]
  ResponseIo { source: reqwest::Error },

  #[error("Error parsing json response: {}", source)]
  JsonParse { source: serde_json::Error },

  #[error("Unexpected API Response")]
  UnexpectedResponse { response: Object },

  #[error("API Error {}({}): {}", .error.code, .error.status, .error.message)]
  Api { error: ErrorResponse },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct StatusCode(NonZeroU16);

impl Display for StatusCode {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ErrorResponse {
  pub status: StatusCode,
  pub code: ErrorCode,
  pub message: String,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
  /// The request body could not be decoded as JSON.
  InvalidJson,
  /// The request URL is not valid.
  InvalidRequestUrl,
  /// This request is not supported.
  InvalidRequest,
  /// The request body does not match the schema for the expected parameters. Check the "message" property for more details.
  MissionVersion,
  /// The bearer token is not valid.
  Unauthorized,
  /// Given the bearer token used, the client doesn't have permission to perform this operation.
  RestrictedResource,
  /// Given the bearer token used, the resource does not exist. This error can also indicate that the resource has not been shared with owner of the bearer token.
  ObjectNotFound,
  /// The transaction could not be completed, potentially due to a data collision. Make sure the parameters are up to date and try again.
  ConflictError,
  /// This request exceeds the number of requests allowed. Slow down and try again. More details on rate limits.
  RateLimited,
  /// An unexpected error occurred. Reach out to NVD support.
  InternalServerError,
  /// NVD is unavailable. Try again later. This can occur when the time to respond to a request takes longer than 60 seconds, the maximum request timeout.
  ServiceUnavailable,
  #[serde(other)] // serde issue #912
  Unknown,
}

impl Display for ErrorCode {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{self:?}")
  }
}
