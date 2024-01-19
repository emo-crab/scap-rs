use super::request_get;
use crate::error::Error;
use crate::modules::cpe::{ProductWithVendor, QueryCpe};
use crate::modules::ListResponse;

pub async fn product_list(
  query: QueryCpe,
) -> Result<ListResponse<ProductWithVendor, QueryCpe>, Error> {
  request_get::<QueryCpe, ListResponse<ProductWithVendor, QueryCpe>>("product/".to_string(), query)
    .await
}
