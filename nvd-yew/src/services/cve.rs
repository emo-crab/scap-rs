use crate::error::Error;
use super::request_get;
use crate::modules::cve::CveInfoList;
pub async fn cve_list() -> Result<CveInfoList, Error> {
    request_get::<CveInfoList>("/cve".to_string()).await
}