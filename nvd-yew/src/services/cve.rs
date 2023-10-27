use super::request_get;
use crate::error::Error;
use crate::modules::cve::{CveInfoList, QueryCve};

pub async fn cve_list(query: QueryCve) -> Result<CveInfoList, Error> {
  request_get::<QueryCve, CveInfoList>("cve".to_string(), query).await
}
