use actix_cors::Cors;
use actix_web::{get, http, middleware, web, App, HttpServer, Responder};
use nvd_api::api::api_route;
use nvd_api::init_db_pool;

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
  let connection_pool = init_db_pool();
  env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
  HttpServer::new(move || {
    let cors = Cors::default()
      .allowed_origin_fn(|origin, _req_head| origin.as_bytes().ends_with(b".kali-team.cn"))
      .allowed_headers(vec![http::header::ACCEPT])
      .allowed_header(http::header::CONTENT_TYPE)
      .max_age(3600);
    App::new()
      .wrap(cors)
      .wrap(middleware::Logger::default())
      .app_data(web::Data::new(connection_pool.clone()))
      .service(web::scope("/api").configure(api_route))
  })
  .bind(("127.0.0.1", 8080))?
  .run()
  .await
}
