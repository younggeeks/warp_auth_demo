use jsonwebtoken::{encode, errors::Error, Algorithm, EncodingKey, Header};
use models::Claims;
use warp::reject::{Reject, Rejection};

pub mod models;

pub mod handlers;
