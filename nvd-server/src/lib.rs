pub mod api;
pub mod error;

use crate::error::NVDApiError;
use actix_web::HttpResponse;
use nvd_model::Pool;

pub type ApiResponse = Result<HttpResponse, NVDApiError>;

#[cfg(test)]
mod tests {

  #[test]
  fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
  }
}
