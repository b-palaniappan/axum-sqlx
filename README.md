# Axum SQLx
- REST API with Axum, SQLx using PostgreSQL DB.

## PostgreSQL in Docker
```bash
docker run --name local-postgres -e POSTGRES_PASSWORD=D0eFU4uh6sav4X64HurgN -p 5432:5432 -d postgres:alpine
```
- User ID and Password: `postgres` and `D0eFU4uh6sav4X64HurgN`
- Run migration using: `sqlx migrate run` to create table in PostgreSQL.

## Generating RSA Keys
```bash
openssl genrsa -out axum_private.pem 3072
openssl rsa -in axum_private.pem -pubout -out axum_public.pem
```

## OpenAPI documentation
- Access OpenAPI docs using `/scalar` endpoint.

## Features
- [x] Create new user
- [x] Get all users with pagination logic.
- [x] Get one user by user id.
- [x] Patch partial user data by user id.
- [x] Soft Delete user by user id.
- [x] Global exception handling.
- [ ] gRPC in Axum framework.
- [x] Argon2id password hashing algorithm.
- [x] Add openapi / Swagger UI documentation.
- [ ] JWT token based authentication and authorization.
- [x] Add caching with Redis.
- [x] Add logging using tracing.
- [ ] Add secret manager to store secrets.
- [x] Rest api client using reqwest.
- [x] Unit and Integration testing.
- [x] Dockerize the application.
- [ ] CI/CD pipeline using GitHub Actions.

## Caching
- Use Redis as cache store.
- When use login-in create a JWT token and store the user profile info, permissions and roles in Redis with TTL of 1 day, which is same as JWT token expiry.
- On each JWT token check, validate the token and get the user profile info from Redis to get the permissions and roles.
- On logout, or token expiry, delete the user profile info from Redis.

## Roles and Permissions
### Roles
- ADMIN
- USER
- SERVICE

### Permissions
- READ
- WRITE

## Testing
### Integration Tests
To run the integration tests:

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_create_user

# Run tests with output
cargo test -- --nocapture
```

Note: Integration tests require a running PostgreSQL database and Redis instance. The tests will use the database connection specified in the `TEST_DATABASE_URL` environment variable, or will fall back to `DATABASE_URL` if not specified.
