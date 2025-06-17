//! Configuration management for the application.
//!
//! This module centralizes all configuration settings and provides validation
//! for required configuration at startup.

use std::fmt::Debug;
use worker::Env;

/// Constants for KV storage keys
pub const KV_STORAGE_BINDING: &str = "KV_STORAGE";
pub const SIGNING_KEY: &str = "keystore::sig";
pub const ENCRYPTION_KEY: &str = "keystore::enc";

/// Application configuration
#[derive(Clone, Debug)]
pub struct Config {
    /// The URL of the authentication server
    pub auth_server_url: String,
    /// The client ID for OAuth authentication
    pub client_id: String,
    /// The client secret for OAuth authentication
    pub client_secret: String,
    /// The application URL
    pub app_url: String,
    /// Whether the application is running in development mode
    pub dev_mode: bool,
}

impl Config {
    /// Create a new configuration from environment variables
    ///
    /// # Arguments
    ///
    /// * `env` - The environment containing configuration values
    ///
    /// # Returns
    ///
    /// A Result containing the configuration or an error if required values are missing
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let auth_server_url = env
            .secret("AUTH_SERVER_URL")
            .map_err(|_| ConfigError::MissingValue("AUTH_SERVER_URL"))?
            .to_string();

        let client_id = env
            .secret("CLIENT_ID")
            .map_err(|_| ConfigError::MissingValue("CLIENT_ID"))?
            .to_string();

        let client_secret = env
            .secret("CLIENT_SECRET")
            .map_err(|_| ConfigError::MissingValue("CLIENT_SECRET"))?
            .to_string();

        let app_url = env
            .secret("APP_URL")
            .map_err(|_| ConfigError::MissingValue("APP_URL"))?
            .to_string();

        let dev_mode = env
            .var("DEV_MODE")
            .map(|var| var.to_string() == "true")
            .unwrap_or(false);

        Ok(Config {
            auth_server_url,
            client_id,
            client_secret,
            app_url,
            dev_mode,
        })
    }
}

/// Errors that can occur when loading configuration
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required configuration value is missing
    #[error("Missing required configuration value: {0}")]
    MissingValue(&'static str),
}