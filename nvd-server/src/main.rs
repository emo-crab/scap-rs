use actix_cors::Cors;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{http, middleware, web, App, HttpServer};

use nvd_server::api::api_route;
use nvd_server::init_db_pool;

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
      .service(
        actix_files::Files::new("/", "dist")
          .index_file("index.html")
          .default_handler(index),
      )
  })
  .bind(("0.0.0.0", 8888))?
  .run()
  .await
}

// 支持单页面应用，强制重定向到首页文件
async fn index(reqs: ServiceRequest) -> actix_web::Result<ServiceResponse> {
  let (req, _) = reqs.into_parts();
  let file = actix_files::NamedFile::open_async("dist/index.html").await?;
  let res = file.into_response(&req);
  Ok(ServiceResponse::new(req, res))
}
