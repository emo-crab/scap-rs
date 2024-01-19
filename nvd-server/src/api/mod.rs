mod cve_api;
mod cwe_api;
mod product_api;
mod vendor_api;

use crate::modules::cve_db::QueryCve;
use crate::modules::{Cve, Cwe, Product, Vendor};
use crate::{ApiResponse, Pool};
use actix_web::{get, web, HttpRequest, HttpResponse};
use std::ops::DerefMut;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
paths(
cve_api::api_cve_id,
cve_api::api_cve_list,
cwe_api::api_cwe_id,
cwe_api::api_cwe_list,
product_api::api_product_list,
vendor_api::api_vendor_name,
vendor_api::api_vendor_list,
),
components(schemas(Cve, Cwe, Product, Vendor)),
tags((name = "nvd-rs open api", description = "National Vulnerability Database (NVD) implemented by rust")),
)]
pub struct ApiDoc;

#[get("/sitemap.xml")]
async fn sitemap(req: HttpRequest, pool: web::Data<Pool>) -> ApiResponse {
  let contact = web::block(move || {
    let mut conn = pool.get()?;
    Cve::query(conn.deref_mut(), &QueryCve::default())
  })
  .await??;
  let mut sitemap = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
  for cve in contact.result {
    let loc = format!("<url>\n<loc>{}://{}/cve/{}</loc>\n\t<lastmod>{}</lastmod>\n\t<changefreq>daily</changefreq>\n\t<priority>0.9</priority>\n</url>\n",
                      req.connection_info().scheme(),
                      req.connection_info().host(),
                      cve.id,
                      cve.updated_at.format("%Y-%m-%d"),
    );
    sitemap.push_str(&loc);
  }
  sitemap.push_str("</urlset>");
  Ok(HttpResponse::Ok().content_type("text/xml").body(sitemap))
}

pub fn api_route(cfg: &mut web::ServiceConfig) {
  cfg
    .service(
      web::scope("/cve")
        .service(cve_api::api_cve_id)
        .service(cve_api::api_cve_list),
    )
    .service(
      web::scope("/vendor")
        .service(vendor_api::api_vendor_name)
        .service(vendor_api::api_vendor_list),
    )
    .service(
      web::scope("/cwe")
        .service(cwe_api::api_cwe_id)
        .service(cwe_api::api_cwe_list),
    )
    .service(web::scope("/product").service(product_api::api_product_list));
}
