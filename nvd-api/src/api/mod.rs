mod cve_api;
use actix_web::web;

pub fn api_route(cfg: &mut web::ServiceConfig) {
    cfg.service(cve_api::api_cve_id);
}