use crate::{ApiResponse, Pool};
use actix_web::{get, web, HttpResponse};
use nvd_model::cve::{Cve, QueryCve};
use std::ops::DerefMut;

#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/cve",
params(
("id", description = "CVE ID")
),
responses((status = 200, description = "List cve by id", body = Cve))
))]
#[get("/{id}")]
async fn api_cve_id(id: web::Path<String>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cve::query_by_id(conn.deref_mut(), &id)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/cve",
params(QueryCve),
responses((status = 200, description = "List cve items"))
))]
#[get("/")]
async fn api_cve_list(args: web::Query<QueryCve>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cve::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
