use super::request_get;
use crate::error::Error;
use crate::modules::ListResponse;
use nvd_model::product::{ProductWithVendor, QueryProduct};

pub async fn product_list(
  query: QueryProduct,
) -> Result<ListResponse<ProductWithVendor, QueryProduct>, Error> {
  request_get::<QueryProduct, ListResponse<ProductWithVendor, QueryProduct>>(
    "product/".to_string(),
    query,
  )
  .await
}
