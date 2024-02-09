use crate::{ApiResponse, Pool};
use actix_web::{get, web, HttpResponse};
use nvd_model::product::{Product, QueryProduct};
use std::ops::DerefMut;

#[cfg_attr(feature = "openapi", utoipa::path(
context_path = "/api/product",
params(QueryProduct),
responses((status = 200, description = "List product items"))
))]
#[get("/")]
async fn api_product_list(args: web::Query<QueryProduct>, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Product::query(conn.deref_mut(), &args)
  })
  .await??;
  Ok(HttpResponse::Ok().json(contact))
}
