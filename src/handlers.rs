use handle_errors::error::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use warp::{reject::Rejection, reply::Reply};

use crate::models::{Claims, Login, Registration, Role, User};

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
            Err(e) => {
                return Err(warp::reject::custom(Error::InvalidCredentials));
            }
        };

    let expiry_date = chrono::Utc::now() + chrono::Duration::hours(2);

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
