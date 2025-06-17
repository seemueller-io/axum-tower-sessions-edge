//! Error handling for the application.
//!
//! This module provides centralized error handling functionality,
//! including middleware for handling introspection errors.

use axum::response::{IntoResponse, Redirect, Response};
use http::StatusCode;

/// Middleware for handling introspection errors.
///
/// This middleware checks for specific error headers and redirects
/// to the login page when appropriate.
pub async fn handle_introspection_errors(mut response: Response) -> Response {
    let x_error_header_value = response
        .headers()
        .get("x-introspection-error")
        .and_then(|header_value| header_value.to_str().ok());

    // not used but is available
    let x_session_header_value = response
        .headers()
        .get("x-session")
        .and_then(|header_value| header_value.to_str().ok());

    match response.status() {
        StatusCode::UNAUTHORIZED => {
            if let Some(x_error) = x_error_header_value {
                if x_error == "unauthorized" {
                    return Redirect::to("/login").into_response();
                }
            }
            response
        }
        StatusCode::BAD_REQUEST => {
            if let Some(x_error) = x_error_header_value {
                if x_error == "invalid schema"
                    || x_error == "invalid header"
                    || x_error == "introspection error"
                {
                    return Redirect::to("/login").into_response();
                }
            }
            response
        }
        StatusCode::FORBIDDEN => {
            if let Some(x_error) = x_error_header_value {
                if x_error == "user is inactive" {
                    return Redirect::to("/login").into_response();
                }
            }
            response
        }
        StatusCode::NOT_FOUND => {
            if let Some(x_error) = x_error_header_value {
                if x_error == "user was not found" {
                    return Redirect::to("/login").into_response();
                }
            }
            response
        }
        StatusCode::INTERNAL_SERVER_ERROR => {
            if let Some(x_error) = x_error_header_value {
                if x_error == "missing config" {
                    return Redirect::to("/login").into_response();
                }
            }
            response
        }
        _ => response,
    }
}