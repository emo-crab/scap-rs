use crate::models::vendor_db::QueryVendor;
use crate::models::Vendor;
use crate::{ApiResponse, Pool};
use actix_web::{get, web, Error, HttpResponse};
use std::ops::DerefMut;

#[get("/{name}")]
async fn api_vendor_name(
  name: web::Path<String>,
  pool: web::Data<Pool>,
) -> Result<HttpResponse, Error> {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Vendor::query_by_name(conn.deref_mut(), &name)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}

#[get("")]
async fn api_vendor_list(args: web::Query<QueryVendor>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Vendor::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
