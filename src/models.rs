use argon2::{self, Config};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub email: String,
    pub username: String,
    pub roles: Vec<Role>,
    pub exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Role {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Registration {
    pub email: String,
    pub password: String,
    pub username: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Login {
    pub password: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: String,
}

impl User {
    pub fn new(id: i32, username: String, email: String, password: String) -> Self {
        let password_hash = User::hash_password(&password);
        let created_at = Utc::now().to_rfc3339();

        User {
            id,
            username,
            email,
            password_hash,
            created_at,
        }
    }

    fn hash_password(password: &str) -> String {
        let config = Config::default();
        let salt = b"somersalt";
        argon2::hash_encoded(password.as_bytes(), salt, &config).unwrap()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        argon2::verify_encoded(&self.password_hash, password.as_bytes()).unwrap_or(false)
    }
}
