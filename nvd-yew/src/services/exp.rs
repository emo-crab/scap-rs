use super::request_get;
use crate::error::Error;
use crate::modules::ListResponse;
use nvd_model::exploit::{Exploit, QueryExploit};

pub async fn exploit_list(
  query: QueryExploit,
) -> Result<ListResponse<Exploit, QueryExploit>, Error> {
  request_get::<QueryExploit, ListResponse<Exploit, QueryExploit>>("exp/".to_string(), query).await
}
