use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 32-hex secret core, deterministic per telegram_id. Stable, not stored.
pub fn proxy_secret(master_key: &str, telegram_id: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(telegram_id.to_string().as_bytes());
    let full = mac.finalize().into_bytes();
    hex::encode(&full[..16])
}

/// tg://proxy link with dd-prefixed secret.
pub fn build_link(host: &str, port: &str, secret_core: &str) -> String {
    format!("tg://proxy?server={host}&port={port}&secret=dd{secret_core}")
}

/// One-tap web "add proxy" url.
pub fn build_web_link(host: &str, port: &str, secret_core: &str) -> String {
    format!("https://t.me/proxy?server={host}&port={port}&secret=dd{secret_core}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_deterministic_and_32_hex() {
        let a = proxy_secret("test-master-key-32-chars-minimum!", 123456789);
        let b = proxy_secret("test-master-key-32-chars-minimum!", 123456789);
        assert_eq!(a, b, "same input => same secret");
        assert_eq!(a.len(), 32, "16 bytes => 32 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn secret_differs_per_user_and_key() {
        let k = "test-master-key-32-chars-minimum!";
        assert_ne!(proxy_secret(k, 1), proxy_secret(k, 2));
        assert_ne!(proxy_secret(k, 1), proxy_secret("other-key-also-32-chars-minimum!!", 1));
    }

    #[test]
    fn link_format() {
        assert_eq!(
            build_link("svoiweb.ru", "8444", "b6954bf0bdb553293b0a4d751c9205c7"),
            "tg://proxy?server=svoiweb.ru&port=8444&secret=ddb6954bf0bdb553293b0a4d751c9205c7"
        );
        assert_eq!(
            build_web_link("svoiweb.ru", "8444", "b6954bf0bdb553293b0a4d751c9205c7"),
            "https://t.me/proxy?server=svoiweb.ru&port=8444&secret=ddb6954bf0bdb553293b0a4d751c9205c7"
        );
    }
}
