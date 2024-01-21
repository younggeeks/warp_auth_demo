-- Add migration script here

CREATE TABLE if not exists users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at VARCHAR(255) NOT NULL
);