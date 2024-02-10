pub mod cpe;
pub mod cve;
pub mod exp;
mod request;

use crate::error::Error;
use request::request_get;

pub enum FetchState<T> {
  Success(T),
  Failed(Error),
}
