use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use warp::{reject::Rejection, reply::Reply};

use crate::models::{Claims, Login, Registration, Role, User};

pub async fn register(user: Registration) -> Result<impl Reply, Rejection> {
    let user = User::new(32, user.username, user.email, user.password);

    let token = generate_jwt_token(Claims {
        email: user.email,
        username: user.username,
        roles: vec![Role::User],
        exp: 1234568489,
    })
    .unwrap();

    Ok(warp::reply::json(&token))
}

pub async fn login(user: Login) -> Result<impl Reply, Rejection> {
    // check if user exists in the DB then verify password
    let password = user.password;
    let username = user.username;

    Ok(warp::reply::json(&username))
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
