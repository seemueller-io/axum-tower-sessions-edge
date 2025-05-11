use custom_error::custom_error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::Path;

use crate::credentials::jwt::JwtClaims;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    client_id: String,
    app_id: String,
    key_id: String,
    key: String,
}

custom_error! {
    pub ApplicationError
        Io{source: std::io::Error} = "unable to read from file: {source}",
        Json{source: serde_json::Error} = "could not parse json: {source}",
        Key{source: jsonwebtoken::errors::Error} = "could not parse RSA key: {source}",
}

impl Application {
    pub fn load_from_file<P: AsRef<Path>>(file_path: P) -> Result<Self, ApplicationError> {
        let data = read_to_string(file_path).map_err(|e| ApplicationError::Io { source: e })?;
        Application::load_from_json(data.as_str())
    }
    
    pub fn load_from_json(json: &str) -> Result<Self, ApplicationError> {
        let sa: Application =
            serde_json::from_str(json).map_err(|e| ApplicationError::Json { source: e })?;
        Ok(sa)
    }
    
    pub fn create_signed_jwt(&self, audience: &str) -> Result<String, ApplicationError> {
        let key = EncodingKey::from_rsa_pem(self.key.as_bytes())
            .map_err(|e| ApplicationError::Key { source: e })?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.to_string());
        let claims = JwtClaims::new(&self.client_id, audience);
        let jwt = encode(&header, &claims, &key)?;

        Ok(jwt)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all)]

    use std::fs::File;
    use std::io::Write;

    use super::*;

    const APPLICATION: &str = r#"
    {
        "type": "application",
        "keyId": "181963758610940161",
        "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwT2YZJytkkZ1DDM3dcu1OA8YPzHu6XR8HotdMNRnV75GhOT4\nB7zDtdtoP8w/1NHHPEJ859e0kYhrrnKikOKLS6fS1KRsmqR5ZvTq8SlZ2mq3RcX2\nebZx5dQt36INij/WXdsBmjM/yfWvqqWBSb0L/186DaWwmmIxoXWe873vxRmlzblg\nGd8Nu07s9YTREbGPbtFVHEUM6xI4oIe8HJ0e1+JBkiGqk31Cogo0FoAxrOAg0Sf4\n5XiUMYIjzqh8673F9SC4IpVxG22mpFk3vDFuAITaStWYbiH2hPJNKWyX9HDCZb1D\nDqa3wZBDiLqWxh22hNZ6ZIe+3UoSGWsPBH+E1wIDAQABAoIBAD2v5QsRPRN57HmF\njAnNir8nimz6CrN53Pl/MbOZypenBSn9UfReXPeb3+6lzCarBPgGnYsBQAJJU16v\n95daym7PVy1Mg+Ll6F9mhe2Qbr+b23+pj2IRTNC6aB6Aw+PDNzJk7GEGRTG6fWZz\nSQ96Cu9tvcGHiBXwjLlnK+PRWU5IsCiLsjT4xBXsMLMw3YOdMK5z58sqr+SnNEyq\nRHoEvi9aC94WrargVB45Yx+81YNW8uQ5rMDmYaJC5a7ENz522SlAuf4T+fAGJ/HE\n/qbZGD4YwlLqAFDgewQ+5tEWEus3zgY2MIR7vN2zXU1Ptk+mQkXZl/Pxdp7q1xU+\nvr/kcykCgYEAy7MiIAzc1ctQDvkk3HiespzdQ/sC7+CGsBzkyubRc9Oq/YR7GfVK\nGTuDEDlWwx92VAvJGDWRa3T426YDyqiPj66uo836sgL15Uigg5afZun2bqGC78le\nBhSy9b+0YDHPa87GxtKt9UmMoB6WdmoPzOkLEEGS7eesmk2DDgY+QSUCgYEA8tr/\n3PawigL1cxuFpcO1lH6XUspGeAo5yB8FXvfW5g50e37LgooIvOFgUlYuchxwr6uh\nW+CUAWmm4farsgvMBMPYw+PbkCTi/xemiiDmMHUYd7sJkTl0JXApq3pZsNMg4Fw/\n29RynmcG8TGe2dkwrWp1aBYjvIHwEHuNHHTTA0sCgYBtSUFAwsXkaj0cm2y8YHZ8\nS46mv1AXFHYOnKHffjDXnLN7ao2FIsXLfdNWa/zxmLqqYtxUAcFwToSJi6szGnZT\nVxvZRFSBFveIOQvtLW1+EH4nYr3WGko4pvhQwrZqea7YH0skNrogBILPEToWc9bg\nUBOgeB31R7uh2X47kvvphQKBgQDWc60dYnniZVp5mwQZrQjbaC4YXaZ8ugrsPPhx\nNEoAPSN/KihrzZiJsjtsec3p1lNrzRNgHqCT3sgPIdPcFa7DRm5UDRIF54zL1gaq\nUwLyJ3TDxdZc928o4DLryc8J5mZRuSRq6t+MIU5wDnFHzhK+EBQ9Jc/I1rU22ONz\nDXaIoQKBgH14Apggo0o4Eo+OnEBRFbbDulaOfVLPTK9rktikbwO1vzDch8kdcwCU\nsvtRXHjDQL93Ih/8S9aDJZoSDulwr3VUsuDiDEb4jfYmP2sbNO4nIJt+SBMhVOXV\nt7E/uWK28X0GL/bIUzSMMgTfdjhXEtJW+s6hQU1fG+9U1qVTQ2R/\n-----END RSA PRIVATE KEY-----\n",
        "appId": "181963751145079041",
        "clientId": "181963751145144577@zitadel_rust_test"
    }"#;

    #[test]
    fn load_successfully_from_json() {
        let sa = Application::load_from_json(APPLICATION).unwrap();

        assert_eq!(sa.client_id, "181963751145144577@zitadel_rust_test");
        assert_eq!(sa.key_id, "181963758610940161");
    }

    #[test]
    fn load_successfully_from_file() {
        let mut file = File::create("./temp_app").unwrap();
        file.write_all(APPLICATION.as_bytes())
            .expect("Could not write temp.");

        let sa = Application::load_from_file("./temp_app").unwrap();

        assert_eq!(sa.client_id, "181963751145144577@zitadel_rust_test");
        assert_eq!(sa.key_id, "181963758610940161");
    }

    #[test]
    fn load_faulty_from_json() {
        let err = Application::load_from_json("{1234}").unwrap_err();

        if let ApplicationError::Json { source: _ } = err {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn load_faulty_from_file() {
        let err = Application::load_from_file("./foobar").unwrap_err();

        if let ApplicationError::Io { source: _ } = err {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn creates_a_signed_jwt() {
        let sa = Application::load_from_json(APPLICATION).unwrap();
        let claims = sa.create_signed_jwt("https://zitadel.cloud").unwrap();

        assert_eq!(&claims[0..5], "eyJ0e");
    }
}
