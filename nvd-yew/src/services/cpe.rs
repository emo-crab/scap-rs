use super::request_get;
use crate::error::Error;
use crate::modules::cpe::{Product, QueryCpe, Vendor};
use crate::modules::ListResponse;

pub async fn vendor_list(query: QueryCpe) -> Result<ListResponse<Vendor, QueryCpe>, Error> {
  request_get::<QueryCpe, ListResponse<Vendor, QueryCpe>>("vendor".to_string(), query).await
}

pub async fn product_list(query: QueryCpe) -> Result<ListResponse<Product, QueryCpe>, Error> {
  request_get::<QueryCpe, ListResponse<Product, QueryCpe>>("product".to_string(), query).await
}
