//! Tests for the creation of a new `did:webvh` document and associated log
//! signer.

use credibil_did::webvh::{CreateBuilder, Witness, WitnessWeight};
use credibil_did::{DocumentBuilder, KeyId, Service, VerificationMethod};
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating a new `did:webvh` document and associated log
// entry. Should just work without errors.
#[tokio::test]
async fn create_ok() {
    let signer = Keyring::generate(&Vault, "wvhc", "signing", Curve::Ed25519)
        .await
        .expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let auth_entry =
        Keyring::generate(&Vault, "wvhc", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = auth_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let auth_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethod::build()
        .key(update_multi.clone())
        .key_id(KeyId::Authorization(auth_multi));
    let svc = Service::build()
        .id("whois")
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois");
    let builder = DocumentBuilder::new().verification_method(vm).service(svc);

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes()).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let witness_1 =
        Keyring::generate(&Vault, "w1", "signing", Curve::Ed25519).await.expect("should generate");
    let vk = witness_1.verifying_key().await.expect("should get key");
    let multi_1 =
        PublicKeyJwk::from_bytes(&vk.to_bytes()).unwrap().to_multibase().expect("should convert");

    let witness_2 =
        Keyring::generate(&Vault, "w2", "signing", Curve::Ed25519).await.expect("should generate");
    let vk = witness_2.verifying_key().await.expect("should get key");
    let multi_2 =
        PublicKeyJwk::from_bytes(&vk.to_bytes()).unwrap().to_multibase().expect("should convert");

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: format!("did:key:{multi_1}#{multi_1}"),
                weight: 50,
            },
            WitnessWeight {
                id: format!("did:key:{multi_2}#{multi_2}"),
                weight: 40,
            },
        ],
    };

    let result = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .update_keys(vec![update_multi])
        .next_key(&next_multi)
        .witness(&witnesses)
        .ttl(60)
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let log_entry =
        serde_json::to_string_pretty(&result.log[0]).expect("should serialize log signer");
    println!("{log_entry}");
}
