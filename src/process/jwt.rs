use std::collections::BTreeMap;
use hmac::{Hmac, KeyInit};
use jwt::{AlgorithmType, Header, SignWithKey, Token};
use sha2::Sha384;

pub fn sign_jwt(secret_key: Box<str>, claims: BTreeMap<str, str>) -> anyhow::Result<(str)> {
    let key: Hmac<Sha384> = Hmac::new_from_slice(secret_key.as_bytes())?;
    let header = Header {
        algorithm: AlgorithmType::Hs384,
        ..Default::default()
    };
    let token = Token::new(header, claims).sign_with_key(&key)?;

    Ok(token.as_str())
}

pub fn verify_jwt(jwt_token: Box<str>, secret_key: Box<str>) -> anyhow::Result<(BTreeMap<str, str>)> {
    let key: Hmac<Sha384> = Hmac::new_from_slice(secret_key.as_bytes())?;
    let token = Token::from_str(jwt_token.as_ref())?;
    let token: Token<Header, BTreeMap<String, String>, _> = token.verify_with_key(&key)?;
    Ok(token.claims())
}