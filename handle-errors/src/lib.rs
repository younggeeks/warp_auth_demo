pub mod error {
    use std::fmt::Display;

    use warp::{
        filters::{body::BodyDeserializeError, cors::CorsForbidden},
        http::StatusCode,
        reject::{Reject, Rejection},
        reply::Reply,
    };

    #[derive(Debug, PartialEq)]
    pub enum Error {
        ParseError(std::num::ParseIntError),
        MissingParameters,
        MissingCredentials,
        InvalidCredentials,
        InvalidToken,
        ExpiredSignature,
    }

    impl Reject for Error {}

    impl From<sqlx::Error> for Error {
        fn from(value: sqlx::Error) -> Self {
            match value {
                sqlx::Error::Configuration(_) => todo!(),
                sqlx::Error::Database(_) => todo!(),
                sqlx::Error::Io(_) => todo!(),
                sqlx::Error::Tls(_) => todo!(),
                sqlx::Error::Protocol(_) => todo!(),
                sqlx::Error::RowNotFound => todo!(),
                sqlx::Error::TypeNotFound { type_name: _ } => todo!(),
                sqlx::Error::ColumnIndexOutOfBounds { index: _, len: _ } => todo!(),
                sqlx::Error::ColumnNotFound(_) => todo!(),
                sqlx::Error::ColumnDecode {
                    index: _,
                    source: _,
                } => todo!(),
                sqlx::Error::Decode(_) => todo!(),
                sqlx::Error::AnyDriverError(_) => todo!(),
                sqlx::Error::PoolTimedOut => todo!(),
                sqlx::Error::PoolClosed => todo!(),
                sqlx::Error::WorkerCrashed => todo!(),
                sqlx::Error::Migrate(_) => todo!(),
                _ => todo!(),
            }
        }
    }

    impl Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match *self {
                Error::ParseError(ref err) => {
                    write!(f, "Can not parse parameter: {}", err)
                }
                Error::MissingParameters => write!(f, "Missing Parameter"),
                Error::MissingCredentials => write!(f, "Missing Credentials"),
                Error::InvalidCredentials => write!(f, "Invalid Credentials"),
                Error::InvalidToken => write!(f, "Invalid Token"),
                Error::ExpiredSignature => write!(f, "Expired Signature"),
                _ => write!(f, "Unknown Error"),
            }
        }
    }

    #[derive(Debug)]
    struct InvalidId;

    impl Reject for InvalidId {}

    pub async fn return_error(r: Rejection) -> Result<impl Reply, Rejection> {
        if let Some(error) = r.find::<BodyDeserializeError>() {
            Ok(warp::reply::with_status(error.to_string(), StatusCode::BAD_REQUEST))
        } else if let Some(error) = r.find::<Error>() {
            println!("{:?}", error);
            if error == &Error::InvalidCredentials {
                return Ok(warp::reply::with_status(
                    error.to_string(),
                    StatusCode::BAD_REQUEST,
                ));
            }
            Ok(warp::reply::with_status(error.to_string(), StatusCode::BAD_REQUEST))
        } else if let Some(error) = r.find::<CorsForbidden>() {
            Ok(warp::reply::with_status(error.to_string(), StatusCode::FORBIDDEN))
        } else {
            Ok(warp::reply::with_status(
                "Route not found".to_string(),
                StatusCode::NOT_FOUND,
            ))
        }
    }
}
