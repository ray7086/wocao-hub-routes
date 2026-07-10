use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::StreamExt;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const ROUTE_FILE_NAME: &str = "routes.enc";
const MANIFEST_FILE_NAME: &str = "manifest.json";
const SIGNATURE_FILE_NAME: &str = "routes.sig";
const ROUTE_MAGIC: &[u8; 8] = b"WCRTE001";
const ROUTE_AAD: &[u8] = b"wocao-hub-routes/v1";
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_LIFETIME_HOURS: i64 = 72;

#[derive(Debug, Error)]
pub enum PublishError {
    #[error("missing required environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("subscription URL must use HTTPS")]
    InvalidSubscriptionUrl,
    #[error("subscription request failed")]
    SubscriptionRequest,
    #[error("subscription endpoint returned HTTP {0}")]
    SubscriptionStatus(u16),
    #[error("subscription response is empty")]
    EmptySubscription,
    #[error("subscription response exceeds the 8MB limit")]
    SubscriptionTooLarge,
    #[error("route encryption key must be 32 bytes encoded as Base64")]
    InvalidEncryptionKey,
    #[error("route signing key is invalid")]
    InvalidSigningKey,
    #[error("route encryption failed")]
    Encryption,
    #[error("secure random generation failed")]
    Random,
    #[error("manifest serialization failed")]
    ManifestSerialization(#[from] serde_json::Error),
    #[error("file operation failed")]
    FileOperation(#[from] std::io::Error),
    #[error("bundle lifetime must be between 1 and 720 hours")]
    InvalidLifetime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteManifest {
    pub schema_version: u32,
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub route_file: String,
    pub route_sha256: String,
    pub route_size: u64,
    pub encryption: String,
    pub key_id: String,
}

pub struct PublisherSettings {
    pub subscription_url: Url,
    pub encryption_key: Zeroizing<[u8; 32]>,
    pub signing_key: SigningKey,
    pub key_id: String,
    pub output_directory: PathBuf,
    pub lifetime: ChronoDuration,
}

impl PublisherSettings {
    pub fn from_environment() -> Result<Self, PublishError> {
        let subscription_url = required_environment("SUBSCRIPTION_URL")?;
        let subscription_url =
            Url::parse(&subscription_url).map_err(|_| PublishError::InvalidSubscriptionUrl)?;
        validate_subscription_url(&subscription_url)?;

        let encryption_key =
            decode_encryption_key(&required_environment("ROUTE_ENCRYPTION_KEY_B64")?)?;
        let signing_key = load_signing_key()?;
        let key_id = env::var("ROUTE_KEY_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "v1".to_owned());
        let output_directory = env::var_os("ROUTE_OUTPUT_DIRECTORY")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("public"));
        let lifetime_hours = env::var("ROUTE_BUNDLE_LIFETIME_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(DEFAULT_LIFETIME_HOURS);
        if !(1..=720).contains(&lifetime_hours) {
            return Err(PublishError::InvalidLifetime);
        }

        Ok(Self {
            subscription_url,
            encryption_key,
            signing_key,
            key_id,
            output_directory,
            lifetime: ChronoDuration::hours(lifetime_hours),
        })
    }
}

pub async fn publish(settings: &PublisherSettings) -> Result<RouteManifest, PublishError> {
    let subscription = fetch_subscription(&settings.subscription_url).await?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| PublishError::Random)?;
    publish_payload(settings, &subscription, nonce, Utc::now())
}

pub fn publish_payload(
    settings: &PublisherSettings,
    subscription: &[u8],
    nonce: [u8; 24],
    generated_at: DateTime<Utc>,
) -> Result<RouteManifest, PublishError> {
    if subscription.is_empty() {
        return Err(PublishError::EmptySubscription);
    }
    if subscription.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(PublishError::SubscriptionTooLarge);
    }

    let encrypted = encrypt_routes(subscription, &settings.encryption_key, nonce)?;
    let route_hash = Sha256::digest(&encrypted);
    let route_hash_hex = encode_hex(&route_hash);
    let version = format!("{}-{}", generated_at.format("%Y%m%d%H%M%S"), &route_hash_hex[..12]);
    let manifest = RouteManifest {
        schema_version: 1,
        version,
        generated_at,
        expires_at: generated_at + settings.lifetime,
        route_file: ROUTE_FILE_NAME.to_owned(),
        route_sha256: route_hash_hex,
        route_size: encrypted.len() as u64,
        encryption: "xchacha20poly1305".to_owned(),
        key_id: settings.key_id.clone(),
    };
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    let signature = settings.signing_key.sign(&manifest_bytes);
    let signature_bytes = format!("{}\n", STANDARD.encode(signature.to_bytes())).into_bytes();

    fs::create_dir_all(&settings.output_directory)?;
    atomic_write(&settings.output_directory.join(ROUTE_FILE_NAME), &encrypted)?;
    atomic_write(&settings.output_directory.join(MANIFEST_FILE_NAME), &manifest_bytes)?;
    atomic_write(&settings.output_directory.join(SIGNATURE_FILE_NAME), &signature_bytes)?;
    let _ = fs::remove_file(settings.output_directory.join(".gitkeep"));
    Ok(manifest)
}

pub async fn fetch_subscription(url: &Url) -> Result<Vec<u8>, PublishError> {
    validate_subscription_url(url)?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || attempt.url().scheme() != "https" {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| PublishError::SubscriptionRequest)?;
    let response =
        client.get(url.clone()).send().await.map_err(|_| PublishError::SubscriptionRequest)?;
    if !response.status().is_success() {
        return Err(PublishError::SubscriptionStatus(response.status().as_u16()));
    }
    if response.content_length().is_some_and(|length| length > MAX_SUBSCRIPTION_BYTES as u64) {
        return Err(PublishError::SubscriptionTooLarge);
    }

    let mut payload = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| PublishError::SubscriptionRequest)?;
        if payload.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BYTES {
            return Err(PublishError::SubscriptionTooLarge);
        }
        payload.extend_from_slice(&chunk);
    }
    if payload.is_empty() {
        return Err(PublishError::EmptySubscription);
    }
    Ok(payload)
}

fn encrypt_routes(
    subscription: &[u8],
    encryption_key: &[u8; 32],
    nonce: [u8; 24],
) -> Result<Vec<u8>, PublishError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(encryption_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: subscription, aad: ROUTE_AAD })
        .map_err(|_| PublishError::Encryption)?;
    let mut encrypted = Vec::with_capacity(ROUTE_MAGIC.len() + nonce.len() + ciphertext.len());
    encrypted.extend_from_slice(ROUTE_MAGIC);
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

fn required_environment(name: &'static str) -> Result<String, PublishError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(PublishError::MissingEnvironment(name))
}

fn validate_subscription_url(url: &Url) -> Result<(), PublishError> {
    if url.scheme() != "https" || url.host_str().is_none() || url.fragment().is_some() {
        return Err(PublishError::InvalidSubscriptionUrl);
    }
    Ok(())
}

fn decode_encryption_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>, PublishError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded.trim().as_bytes())
            .map_err(|_| PublishError::InvalidEncryptionKey)?,
    );
    let key: [u8; 32] =
        decoded.as_slice().try_into().map_err(|_| PublishError::InvalidEncryptionKey)?;
    Ok(Zeroizing::new(key))
}

fn load_signing_key() -> Result<SigningKey, PublishError> {
    let pem =
        match (env::var("ROUTE_SIGNING_KEY_PEM").ok(), env::var("ROUTE_SIGNING_KEY_FILE").ok()) {
            (Some(pem), _) if !pem.trim().is_empty() => Zeroizing::new(pem),
            (_, Some(path)) if !path.trim().is_empty() => {
                Zeroizing::new(fs::read_to_string(path).map_err(PublishError::FileOperation)?)
            }
            _ => return Err(PublishError::MissingEnvironment("ROUTE_SIGNING_KEY_PEM")),
        };
    SigningKey::from_pkcs8_pem(pem.as_str()).map_err(|_| PublishError::InvalidSigningKey)
}

fn atomic_write(path: &Path, payload: &[u8]) -> Result<(), std::io::Error> {
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or("route-output");
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = fs::write(&temporary, payload).and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;
    use ed25519_dalek::{Signature, Verifier};
    use std::fs;

    #[test]
    fn publishes_encrypted_signed_bundle_without_plaintext() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let settings = PublisherSettings {
            subscription_url: Url::parse("https://example.com/subscription")
                .expect("subscription URL"),
            encryption_key: Zeroizing::new([9_u8; 32]),
            signing_key: signing_key.clone(),
            key_id: "test-v1".to_owned(),
            output_directory: directory.path().to_path_buf(),
            lifetime: ChronoDuration::hours(24),
        };
        let generated_at = DateTime::parse_from_rfc3339("2026-07-10T12:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc);
        let plaintext = b"private route payload fixture";

        let manifest = publish_payload(&settings, plaintext, [3_u8; 24], generated_at)
            .expect("published bundle");
        let encrypted = fs::read(directory.path().join(ROUTE_FILE_NAME)).expect("encrypted routes");
        let manifest_bytes = fs::read(directory.path().join(MANIFEST_FILE_NAME)).expect("manifest");
        let signature_text =
            fs::read_to_string(directory.path().join(SIGNATURE_FILE_NAME)).expect("signature");

        assert!(!encrypted.windows(plaintext.len()).any(|value| value == plaintext));
        assert_eq!(manifest.route_size, encrypted.len() as u64);
        assert_eq!(manifest.route_sha256, encode_hex(&Sha256::digest(&encrypted)));
        let signature_bytes = STANDARD.decode(signature_text.trim()).expect("signature base64");
        let signature = Signature::from_slice(&signature_bytes).expect("signature bytes");
        signing_key.verifying_key().verify(&manifest_bytes, &signature).expect("valid signature");

        let nonce = &encrypted[ROUTE_MAGIC.len()..ROUTE_MAGIC.len() + 24];
        let ciphertext = &encrypted[ROUTE_MAGIC.len() + 24..];
        let cipher = XChaCha20Poly1305::new(Key::from_slice(settings.encryption_key.as_ref()));
        let decrypted = cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: ROUTE_AAD })
            .expect("decrypted routes");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_non_https_subscription_url() {
        let url = Url::parse("http://example.com/subscription").expect("URL");

        assert!(matches!(
            validate_subscription_url(&url),
            Err(PublishError::InvalidSubscriptionUrl)
        ));
    }

    #[test]
    fn debug_errors_do_not_include_subscription_credentials() {
        let error = PublishError::SubscriptionRequest;

        assert!(!error.to_string().contains("token"));
        assert!(!format!("{error:?}").contains("example.com"));
    }
}
