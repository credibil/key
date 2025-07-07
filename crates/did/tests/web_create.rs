//! Tests for the creation of a new `did:web` document.

use credibil_did::web::CreateBuilder;
use credibil_did::{DocumentBuilder, KeyId, Service, VerificationMethod};
use credibil_ecc::{Curve, Keyring, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating a new `did:web` document. Should just work
// without errors.
#[tokio::test]
async fn create_ok() {
    let signer =
        Keyring::generate(&Vault, "wc", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");

    let vm = VerificationMethod::build().key(jwk).key_id(KeyId::Index("key-0".to_string()));
    let svc = Service::build()
        .id("whois")
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois");
    let builder = DocumentBuilder::new().verification_method(vm).service(svc);

    let document = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .build()
        .expect("should build document");

    let json = serde_json::to_string_pretty(&document).expect("should serialize");
    print!("{json}");
}
