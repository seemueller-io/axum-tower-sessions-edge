pub struct Utilities;

impl Utilities {
    pub fn get_pkce_verifier_storage_key(csrf_string: &str) -> String {
        format!("pkce_verifier_{}", csrf_string)
    }

    pub fn get_auth_session_key(csrf_string: &str) -> String {
        format!("csrf_session_{}", csrf_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pkce_verifier_storage_key() {
        let csrf_string = "test_csrf";
        let key = Utilities::get_pkce_verifier_storage_key(csrf_string);
        assert_eq!(key, "pkce_verifier_test_csrf");
    }

    #[test]
    fn test_get_auth_session_key() {
        let csrf_string = "test_csrf";
        let key = Utilities::get_auth_session_key(csrf_string);
        assert_eq!(key, "csrf_session_test_csrf");
    }
}
