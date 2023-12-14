use super::request_get;
use crate::error::Error;
use crate::modules::cpe::{ProductInfoList, QueryProduct, QueryVendor, VendorInfoList};
pub async fn vendor_list(query: QueryVendor) -> Result<VendorInfoList, Error> {
  request_get::<QueryVendor, VendorInfoList>("vendor".to_string(), query).await
}

pub async fn product_list(query: QueryProduct) -> Result<ProductInfoList, Error> {
  request_get::<QueryProduct, ProductInfoList>("product".to_string(), query).await
}
