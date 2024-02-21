use request::request_get;

use crate::error::Error;

pub mod cpe;
pub mod cve;
pub mod kb;
mod request;

pub enum FetchState<T> {
  Success(T),
  Failed(Error),
}
