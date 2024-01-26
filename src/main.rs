use std::future;

use handle_errors::error::return_error;
use handlers::{auth, login, register};
use models::Claims;
use sqlx::PgPool;
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{reject::Rejection, Filter};

mod models;

mod handlers;

#[tokio::main]
async fn main() {
    let log_filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "auth_demo=info,warp=debug".to_owned());

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5436/postgres".to_owned());
    let pool: PgPool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let db_filter = warp::any().map(move || pool.clone());

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json::<models::Registration>())
        .and(db_filter.clone())
        .and_then(register);

    let login = warp::post()
        .and(warp::path("login"))
        .and(warp::body::json::<models::Login>())
        .and(db_filter.clone())
        .and_then(login);

    let dashboard = warp::get()
        .and(warp::path("dashboard"))
        .and(db_filter.clone())
        .and(auth())
        .and_then(handlers::dashboard);

    let routes = register
        .or(login)
        .or(dashboard)
        .with(warp::trace::request())
        .recover(return_error);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

