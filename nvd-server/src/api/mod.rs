mod cve_api;
mod cwe_api;
mod product_api;
mod vendor_api;

use actix_web::web;

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
