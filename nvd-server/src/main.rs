use actix_cors::Cors;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{get, http, middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use std::ops::DerefMut;

use nvd_server::api::api_route;
use nvd_server::modules::cve_db::QueryCve;
use nvd_server::modules::Cve;
use nvd_server::{init_db_pool, ApiResponse, Pool};

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
      .service(sitemap)
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
