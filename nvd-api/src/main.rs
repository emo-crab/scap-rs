use actix_web::{get, web, App, HttpServer, Responder, middleware};
use nvd_api::api::api_route;
use nvd_api::init_db_pool;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {}!", name)
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    let connection_pool = init_db_pool();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(connection_pool.clone()))
            .service(web::scope("/api").configure(api_route))
            .service(greet)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}