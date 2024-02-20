use std::ops::DerefMut;

use actix_web::{get, web, HttpResponse};

use nvd_model::knowledge_base::{KnowledgeBase, QueryKnowledgeBase};

use crate::{ApiResponse, Pool};

#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/kb",
params(QueryKnowledgeBase),
responses((status = 200, description = "List knowledge_base items"))
))]
#[get("/")]
async fn api_kb_list(args: web::Query<QueryKnowledgeBase>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    KnowledgeBase::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
