use nvd_model::knowledge_base::{KnowledgeBase, QueryKnowledgeBase};

use crate::error::Error;
use crate::modules::ListResponse;

use super::request_get;

pub async fn knowledge_base_list(
  query: QueryKnowledgeBase,
) -> Result<ListResponse<KnowledgeBase, QueryKnowledgeBase>, Error> {
  request_get::<QueryKnowledgeBase, ListResponse<KnowledgeBase, QueryKnowledgeBase>>(
    "kb/".to_string(),
    query,
  )
  .await
}
