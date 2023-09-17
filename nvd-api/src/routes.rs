use actix_web::web;
use actix_web::web::{delete, get, post, put};
pub fn api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(
                web::scope("/cve")
                    .route("{id}", get().to(app::features::healthcheck::controllers::index)),
            )
    );
}
