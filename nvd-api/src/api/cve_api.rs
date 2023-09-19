use crate::models::Cve;
use crate::{ApiResponse, Pool};
use actix_web::{get, web, Error, HttpResponse};
use std::ops::DerefMut;

#[get("/cve/{id}")]
async fn api_cve_id(id: web::Path<String>, pool: web::Data<Pool>) -> Result<HttpResponse, Error> {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cve::query_by_id(conn.deref_mut(), &id)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}

#[get("/cve/{id}")]
async fn api_cve_list(id: web::Path<String>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cve::query_by_id(conn.deref_mut(), &id)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
