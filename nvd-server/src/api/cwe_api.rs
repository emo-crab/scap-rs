use crate::error::ApiResult;
use crate::{ApiResponse, Pool};
use actix_web::{get, web, HttpResponse};
use nvd_model::cwe::{Cwe, QueryCwe};
use std::ops::DerefMut;
#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/cwe",
params(
("id", description = "CWE ID")
),
responses((status = 200, description = "List cwe by id", body = [Cwe]))
))]
#[get("/{id}")]
async fn api_cwe_id(id: web::Path<i32>, pool: web::Data<Pool>) -> ApiResult<HttpResponse> {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cwe::query_by_id(conn.deref_mut(), &id)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/cwe",
params(QueryCwe),
responses((status = 200, description = "List cwe items"))
))]
#[get("/")]
async fn api_cwe_list(args: web::Query<QueryCwe>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cwe::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
