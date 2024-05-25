use anyhow::Error;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,         // Optional. Audience
    pub exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: usize,          // Optional. Issued at (as UTC timestamp)
    pub iss: String,         // Optional. Issuer
    pub nbf: usize,          // Optional. Not Before (as UTC timestamp)
    pub sub: String,         // Optional. Subject (whom token refers to)
}

pub fn process_jwt_sign(secret_key: &str, claims: Claims) -> Result<String, Error> {
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some("blabla".to_owned());
    let token = encode(&header, &claims, &EncodingKey::from_secret(secret_key.as_ref()))?;
    Ok(token.as_str().to_string())
}

pub fn process_jwt_verify(jwt_token: &str, secret_key: &str) -> Result<Claims, Error> {
    let token = decode::<Claims>(
        jwt_token,
        &DecodingKey::from_secret(secret_key.as_ref()),
        &Validation::new(Algorithm::HS512),
    )?;

    Ok(token.claims)
}

mod tests {
    use super::*;

    #[test]
    fn test_sign_jwt() -> anyhow::Result<()> {
        let secret_key = "secret_key";
        let claims = Claims {
            aud: "".to_string(),
            exp: 0,
            iat: 0,
            iss: "".to_string(),
            nbf: 0,
            sub: "".to_string(),
        };
        let token = process_jwt_sign(secret_key.into(), claims)?;
        assert_eq!(token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6ImJsYWJsYSJ9.eyJhdWQiOiIiLCJleHAiOjAsImlhdCI6MCwiaXNzIjoiIiwibmJmIjowLCJzdWIiOiIifQ.ZWXJAhTXpQFKaSx1E3sQif5LfmOfNnPYPJbm8CnrK7hmVxDg7tlsxCPTMppA48F8j9dGYqDq1P4P32VyY-kGEg");
        Ok(())
    }

    #[test]
    fn test_verify_jwt() -> anyhow::Result<()> {
        let secret_key = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6ImJsYWJsYSJ9.eyJhdWQiOiIiLCJleHAiOjAsImlhdCI6MCwiaXNzIjoiIiwibmJmIjowLCJzdWIiOiIifQ.ZWXJAhTXpQFKaSx1E3sQif5LfmOfNnPYPJbm8CnrK7hmVxDg7tlsxCPTMppA48F8j9dGYqDq1P4P32VyY-kGEg";
        let claims = Claims {
            aud: "".to_string(),
            exp: 0,
            iat: 0,
            iss: "".to_string(),
            nbf: 0,
            sub: "".to_string(),
        };
        let token = process_jwt_sign(secret_key.into(), claims)?;
        let claims = process_jwt_verify(&token, secret_key)?;
        assert_eq!(claims.aud, "");
        Ok(())
    }
}