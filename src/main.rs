use handlers::{login, register};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use models::Claims;
use sqlx::PgPool;
use tracing_subscriber::fmt::format::FmtSpan;
use warp::Filter;

mod models;

mod handlers;

#[tokio::main]
async fn main() {
    let pool: PgPool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost:5436/postgres")
        .await
        .unwrap();

    let db_filter = warp::any().map(move || pool.clone());

    let get_auth_token = warp::header::<String>("Authorization")
        .map(|auth_header: String| auth_header.replace("Bearer ", ""));

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

    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "auth_demo=info,warp=debug".to_owned());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let routes = register.or(login).with(warp::trace::request());

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
