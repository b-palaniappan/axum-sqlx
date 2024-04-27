create table if not exists sqlx_users
(
    id            bigserial primary key,
    first_name    varchar(50),
    last_name     varchar(50)          not null,
    email         varchar(255)         not null,
    created_at    timestamptz          not null default now(),
    updated_at    timestamptz          not null default now(),
    deleted_at    timestamptz
);
