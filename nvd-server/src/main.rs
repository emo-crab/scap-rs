use actix_cors::Cors;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{guard, http, middleware, web, App, HttpServer};
use nvd_model::init_db_pool;
#[cfg(feature = "openapi")]
use nvd_server::api::ApiDoc;
use nvd_server::api::{api_route, sitemap};
#[cfg(feature = "openapi")]
use utoipa::OpenApi;
#[cfg(feature = "openapi")]
use utoipa_swagger_ui::SwaggerUi;

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
    let secret_key = Key::generate();
    let session = SessionMiddleware::builder(CookieSessionStore::default(), secret_key)
      .cookie_http_only(false)
      .build();
    let mut app = App::new()
      .wrap(cors)
      .wrap(middleware::Logger::default())
      .wrap(session)
      .app_data(web::Data::new(connection_pool.clone()))
      .service(
        web::scope("api")
          .guard(guard::Get())
          .guard(guard::Any(guard::Host("scap.kali-team.cn")).or(guard::Host("127.0.0.1")))
          .configure(api_route),
      )
      .service(sitemap);
    #[cfg(feature = "openapi")]
    {
      let openapi = ApiDoc::openapi();
      app = app.service(
        SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
      );
    }
    app.service(
      actix_files::Files::new("/", "dist")
        .prefer_utf8(true)
        .index_file("index.html")
        .show_files_listing()
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
