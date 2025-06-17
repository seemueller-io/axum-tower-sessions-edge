//! # axum-tower-sessions-edge Documentation
//!
//! This module provides comprehensive documentation for the axum-tower-sessions-edge project.
//! It serves as a central place for understanding the project's architecture, components,
//! and usage patterns.
//!
//! ## Overview
//!
//! axum-tower-sessions-edge is a Rust library that validates incoming requests for defined routes
//! and forwards traffic to the service defined as `PROXY_TARGET`. It's designed to work with
//! Cloudflare Workers and targets the `wasm32-unknown-unknown` platform.
//!
//! ## Features
//!
//! - **OAuth 2.0**: Implementation of the OAuth 2.0 authorization framework
//! - **PKCE (Proof Key for Code Exchange)**: Enhanced security for OAuth 2.0
//! - **Token Introspection**: Validation of OAuth 2.0 tokens
//!
//! ## Architecture
//!
//! The project is organized into several modules:
//!
//! - **api**: Contains the API endpoints for both authenticated and public routes
//! - **axum_introspector**: Handles token introspection with Axum
//! - **credentials**: Manages authentication credentials
//! - **oidc**: Implements OpenID Connect functionality
//! - **session_storage**: Handles session management
//! - **utilities**: Provides utility functions
//! - **zitadel_http**: HTTP client for Zitadel
//!
//! ## Usage
//!
//! ### Basic Setup
//!
//! To use this library, you need to configure it with your OAuth 2.0 provider details:
//!
//! ```rust
//! // Example configuration (not actual code)
//! let introspection_state = IntrospectionStateBuilder::new("https://your-auth-server-url")
//!     .with_basic_auth("your-client-id", "your-client-secret")
//!     .with_introspection_cache(cache)
//!     .build()
//!     .await
//!     .unwrap();
//! ```
//!
//! ### Authentication Flow
//!
//! The library implements a standard OAuth 2.0 flow:
//!
//! 1. User accesses a protected route
//! 2. If not authenticated, they are redirected to the login page
//! 3. User authenticates with the OAuth provider
//! 4. Provider redirects back with an authorization code
//! 5. The code is exchanged for tokens
//! 6. User session is established
//! 7. User is granted access to protected resources
//!
//! ## Components
//!
//! ### IntrospectionState
//!
//! Central component for token introspection and validation:
//!
//! ```rust
//! // Example usage (not actual code)
//! let introspection_state = IntrospectionStateBuilder::new(auth_server_url)
//!     .with_basic_auth(client_id, client_secret)
//!     .with_introspection_cache(cache)
//!     .build()
//!     .await?;
//! ```
//!
//! ### Session Management
//!
//! The library uses tower-sessions for session management:
//!
//! ```rust
//! // Example session setup (not actual code)
//! let session_layer = SessionManagerLayer::new(session_store)
//!     .with_name("session")
//!     .with_expiry(Expiry::OnSessionEnd)
//!     .with_secure(!is_dev);
//! ```
//!
//! ## Deployment
//!
//! This library is designed to be deployed as a Cloudflare Worker. See the README.md for
//! detailed deployment instructions.