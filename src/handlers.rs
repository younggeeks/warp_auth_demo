use std::future;

use handle_errors::error::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use sqlx::PgPool;
use warp::{reject::Rejection, reply::Reply, Filter};

use crate::models::{self, Claims, Login, Registration, Role, User};

pub async fn register(user: Registration, pool: sqlx::PgPool) -> Result<impl Reply, Rejection> {
    let user = User::new(32, user.username, user.email, user.password);

    let created_at = chrono::Utc::now().to_rfc3339();

    match sqlx::query!(
        "INSERT INTO users (id, username, email, password_hash, created_at) VALUES ($1, $2, $3, $4, $5)",
        user.id,
        user.username,
        user.email,
        user.password_hash,
        created_at
    )
    .execute(&pool)
    .await
    {
        Ok(_) => {
            let token = generate_jwt_token(Claims {
                email: user.email,
                username: user.username,
                roles: vec![Role::User],
                exp: 1234568489,
            })
            .unwrap();

            Ok(warp::reply::json(&token))
        }
        Err(e) => {
            return Err(warp::reject::reject());
        }
    }
}

pub async fn login(user: Login, pool: sqlx::PgPool) -> Result<impl Reply, Rejection> {
    let password = &user.password;
    let username = &user.username;

    let found_user: User =
        match sqlx::query_as!(User, "SELECT  * FROM users WHERE username = $1", username)
            .fetch_one(&pool)
            .await
        {
            Ok(found) => found,
            Err(_e) => {
                return Err(warp::reject::custom(Error::InvalidCredentials));
            }
        };

    let expiry_date = chrono::Utc::now() + chrono::Duration::minutes(2);

    if found_user.verify_password(password) {
        let claims = Claims {
            email: found_user.email,
            username: found_user.username,
            roles: vec![Role::User],
            exp: expiry_date.timestamp() as u64,
        };
        return Ok(warp::reply::json(&generate_jwt_token(claims).unwrap()));
    } else {
        Err(warp::reject::custom(Error::InvalidCredentials))
    }
}

pub async fn dashboard(pool: PgPool, claims: Claims) -> Result<impl Reply, Rejection> {
    println!("claims: {:?}", claims);
    Ok(warp::reply::json(&"dashboard"))
}

pub fn generate_jwt_token(claims: Claims) -> Result<String, Rejection> {
    let secret = b"supersecret_key";

    let signing_key = "samaki_67";

    let header =
        Header {
            typ: Some(signing_key.to_owned()),
            alg: Algorithm::HS512,
            ..Default::default()
        };

    let token = match encode(&header, &claims, &EncodingKey::from_secret(secret)) {
        Ok(t) => Ok(t),
        Err(_) => Err(warp::reject::reject()),
    }?;

    Ok(token)
}

// verify jwt token
pub fn verify_token(token: String) -> Result<Claims, Rejection> {
    let token = token.to_owned();
    if token.is_empty() {
        return Err(warp::reject::custom(handle_errors::error::Error::MissingCredentials));
    }
    let data = jsonwebtoken::decode::<models::Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(b"supersecret_key"),
        &jsonwebtoken::Validation::new(Algorithm::HS512),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidToken => handle_errors::error::Error::InvalidToken,
        jsonwebtoken::errors::ErrorKind::InvalidSignature => {
            handle_errors::error::Error::InvalidToken
        }
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            handle_errors::error::Error::ExpiredSignature
        }
        _e => handle_errors::error::Error::InvalidToken,
    })?;

    Ok(data.claims)
}
pub fn auth() -> impl Filter<Extract = (Result<Claims, Rejection>,), Error = warp::Rejection> + Clone
{
    warp::header::<String>("Authorization").and_then(|token: String| {
        let stripped_token = token.strip_prefix("Bearer ");

        let token = match verify_token(stripped_token.unwrap().to_string()) {
            Ok(t) => Ok(Ok(t)),
            Err(e) => {
                println!("error: {:?}", e);
                Err(e)
            }
        };
        future::ready(token)
    })
}
