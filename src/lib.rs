// Re-export the module structure to match the original app
pub mod api {
    pub mod handler;
    pub mod model;
}
pub mod cache;
pub mod config;
pub mod db {
    pub mod entity;
    pub mod repo;
}
pub mod error;
pub mod middleware;
pub mod service;
pub mod util;

// Re-export AppState for convenience
pub use crate::config::app_config::AppState;
// Re-export AccountStatus for convenience
pub use crate::db::entity::user::AccountStatus;
