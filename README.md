# Axum SQLx
- REST API with Axum, SQLx using PostgreSQL DB.

## PostgreSQL in Docker
```bash
docker run --name local-postgres -e POSTGRES_PASSWORD=D0eFU4uh6sav4X64HurgN -p 5432:5432 -d postgres:alpine
```
- User ID and Password: `postgres` and `D0eFU4uh6sav4X64HurgN`
- Run migration using: `sqlx migrate run` to create table in PostgreSQL.

## OpenAPI documentation
- Access OpenAPI docs using `/scalar` endpoint.

## Features
- [x] Create new user
- [x] Get all users with pagination logic.
- [x] Get one user by user id.
- [x] Patch partial user data by user id.
- [ ] Soft Delete user by user id.
- [x] Global exception handling.
- [ ] gRPC in Axum framework.
- [x] Argon2id password hashing algorithm.
- [x] Add openapi / Swagger UI documentation.
- [ ] JWT token based authentication and authorization.
- [ ] Rest api client using reqwest. 
- [ ] Unit and Integration testing.
- [ ] Dockerize the application.
- [ ] CI/CD pipeline using GitHub Actions.
