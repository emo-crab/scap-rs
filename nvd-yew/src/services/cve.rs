use super::request_get;
use crate::error::Error;
use crate::modules::cve::{Cve, CveInfoList, QueryCve};
use crate::modules::cwe::Cwe;
pub async fn cve_list(query: QueryCve) -> Result<CveInfoList, Error> {
  request_get::<QueryCve, CveInfoList>("cve".to_string(), query).await
}
pub async fn cve_details(id: String) -> Result<Cve, Error> {
  request_get::<(), Cve>(format!("cve/{}", id), ()).await
}

pub async fn cwe_details(id: i32) -> Result<Cwe, Error> {
  request_get::<(), Cwe>(format!("cwe/{}", id), ()).await
}
