# Axum SQLx
- REST API with Axum, SQLx using PostgreSQL DB.

## PostgreSQL in Docker
```bash
docker run --name local-postgres -e POSTGRES_PASSWORD=D0eFU4uh6sav4X64HurgN -p 5432:5432 -d postgres:alpine
```
- User ID and Password: `postgres` and `D0eFU4uh6sav4X64HurgN`

## Features
- [x] Create new user
- [x] Get all users with pagination logic.
- [x] Get one user by user id.
- [x] Patch partial user data by user id.
- [ ] Soft Delete user by user id.
- [x] Global exception handling.
- [ ] gRPC in Axum framework.
- [ ] Argon2id password hashing algorithm.
- [ ] JWT token based authentication and authorization.