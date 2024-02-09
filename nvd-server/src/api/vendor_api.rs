use crate::error::ApiResult;
use crate::{ApiResponse, Pool};
use actix_web::{get, web, HttpResponse};
use nvd_model::vendor::db::QueryVendor;
use nvd_model::vendor::Vendor;
use std::ops::DerefMut;
#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/vendor",
params(
("name", description = "Vendor Name")
),
responses((status = 200, description = "List vendor by name", body = [Vendor]))
))]
#[get("/{name}")]
async fn api_vendor_name(
  name: web::Path<String>,
  pool: web::Data<Pool>,
) -> ApiResult<HttpResponse> {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Vendor::query_by_name(conn.deref_mut(), &name)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/vendor",
params(QueryVendor),
responses((status = 200, description = "List vendor items"))
))]
#[get("/")]
async fn api_vendor_list(args: web::Query<QueryVendor>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Vendor::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
