create table if not exists sqlx_users
(
    id         char(24)     not null primary key,
    first_name varchar(50),
    last_name  varchar(50)  not null,
    email      varchar(255) not null unique,
    created_at timestamptz  not null default now(),
    updated_at timestamptz  not null default now(),
    deleted_at timestamptz
);
