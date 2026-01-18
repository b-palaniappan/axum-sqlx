use crate::db::entity::user::{AccountStatus, Users};
use sqlx::Error;
use sqlx::PgPool;

/// Creates a new user in the database.
///
/// This function inserts a new user record into the `users` table with the provided details
/// and returns the created user record.
///
/// # Arguments
///
/// * `pg_pool` - A reference to the PostgreSQL connection pool.
/// * `user_key` - A unique key identifying the user.
/// * `first_name` - An optional first name of the user.
/// * `last_name` - The last name of the user.
/// * `email` - The email address of the user.
/// * `password_hash` - The hashed password of the user.
/// * `password_hmac` - The HMAC of the user's password.
///
/// # Returns
///
/// * `Result<Users, Error>` - Returns the created user record if successful, otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
#[tracing::instrument(
    skip(pg_pool),
    fields(
        db.system = "postgresql",
        db.operation = "INSERT",
        db.table = "users"
    )
)]
pub async fn create_user(
    pg_pool: &PgPool,
    user_key: &String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: &String,
) -> Result<Users, Error> {
    sqlx::query_as!(
        Users,
        r#"
        INSERT INTO users (key, first_name, last_name, email) 
        VALUES ($1, $2, $3, $4) 
        RETURNING id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus", 
            last_login, failed_login_attempts, created_at, updated_at, deleted_at
        "#,
        user_key,
        first_name,
        last_name,
        email,
    )
        .fetch_one(pg_pool)
        .await
}

/// Retrieves a paginated list of users from the database.
///
/// This function executes an SQL `SELECT` query to fetch a list of users from the `users` table,
/// ordered by the creation date in descending order. The results are paginated based on the provided
/// `limit` and `page` parameters.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `limit` - The maximum number of users to retrieve.
/// * `page` - The page number to retrieve.
///
/// # Returns
///
/// * `Result<Vec<Users>, Error>` - Returns a vector of user records if successful, otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
#[tracing::instrument(
    skip(pool),
    fields(
        db.system = "postgresql",
        db.operation = "SELECT",
        db.table = "users"
    )
)]
pub async fn get_users(pool: &PgPool, limit: i64, page: i64) -> Result<Vec<Users>, Error> {
    sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus", 
               last_login, failed_login_attempts, created_at, updated_at, deleted_at
        FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2
        "#,
        limit,
        (page - 1) * limit
    )
        .fetch_all(pool)
        .await
}

/// Counts the total number of users in the database.
///
/// This function executes an SQL `SELECT COUNT(*)` query to count the total number of users
/// in the `users` table.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
///
/// # Returns
///
/// * `Result<i64, Error>` - Returns the total count of users if successful, otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
#[tracing::instrument(
    skip(pool),
    fields(
        db.system = "postgresql",
        db.operation = "SELECT",
        db.table = "users"
    )
)]
pub async fn count_users(pool: &PgPool) -> Result<i64, Error> {
    let count = sqlx::query!("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    Ok(count.count.unwrap_or(0))
}

/// Retrieves a user by their unique key from the database.
///
/// This function executes an SQL `SELECT` query to fetch a user's details from the `users` table
/// based on the provided unique key.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `key` - The unique key identifying the user to be retrieved.
///
/// # Returns
///
/// * `Result<Users, Error>` - Returns the user record if found, otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
/// * The user does not exist.
#[tracing::instrument(
    skip(pool),
    fields(
        db.system = "postgresql",
        db.operation = "SELECT",
        db.table = "users"
    )
)]
pub async fn get_user_by_key(pool: &PgPool, key: &str) -> Result<Users, Error> {
    sqlx::query_as!(
        Users,
        r#"
        SELECT id, key, first_name, last_name, email, email_verified, account_status as "account_status: AccountStatus", 
               last_login, failed_login_attempts, created_at, updated_at, deleted_at
        FROM users WHERE key = $1
        "#,
        key
    )
        .fetch_one(pool)
        .await
}

/// Updates a user's information in the database.
///
/// This function constructs an SQL `UPDATE` query dynamically based on the fields provided
/// in the `update_user_request`. It updates the user's information in the database and returns
/// the updated user record.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `key` - A reference to the unique key identifying the user to be updated.
/// * `update_user_request` - A struct containing the fields to be updated.
///
/// # Returns
///
/// * `Result<Users, Error>` - Returns the updated user record if successful, otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
/// * The user does not exist.
#[tracing::instrument(
    skip(pool),
    fields(
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.table = "users"
    )
)]
pub async fn update_user(
    pool: &PgPool,
    key: &String,
    update_user_request: crate::api::model::user::UpdateUserRequest,
) -> Result<Users, Error> {
    let mut query = String::from("UPDATE users SET ");
    let mut params = Vec::new();
    let mut set_clauses = Vec::new();

    if let Some(first_name) = &update_user_request.first_name {
        set_clauses.push("first_name = $".to_owned() + &(params.len() + 1).to_string());
        params.push(first_name);
    }

    if let Some(last_name) = &update_user_request.last_name {
        set_clauses.push("last_name = $".to_owned() + &(params.len() + 1).to_string());
        params.push(last_name);
    }

    query += &set_clauses.join(", ");
    query += &format!(" WHERE key = ${} RETURNING *", params.len() + 1);
    params.push(&key);

    let mut query = sqlx::query_as(&query);
    for param in &params {
        query = query.bind(param);
    }
    query.fetch_one(pool).await
}

/// Marks a user as deleted in the database.
///
/// This function updates the `account_status` of a user to 'DELETED' if the user is not already marked as deleted.
///
/// # Arguments
///
/// * `pool` - A reference to the PostgreSQL connection pool.
/// * `key` - The unique key identifying the user to be deleted.
///
/// # Returns
///
/// * `Result<(), Error>` - Returns `Ok(())` if the user was successfully marked as deleted,
///   otherwise returns an `Error`.
///
/// # Errors
///
/// This function will return an `Error` if:
/// * There is an issue executing the SQL query.
/// * The user does not exist or is already marked as deleted.
#[tracing::instrument(
    skip(pool),
    fields(
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.table = "users"
    )
)]
pub async fn delete_user(pool: &PgPool, key: &str) -> Result<(), Error> {
    let result = sqlx::query_as!(
        Users,
        "UPDATE users SET account_status = 'DELETED', deleted_at = CURRENT_TIMESTAMP WHERE key = $1 AND account_status <> 'DELETED'",
        key
    )
        .fetch_one(pool)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}
