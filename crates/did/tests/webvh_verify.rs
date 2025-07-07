//! Tests to verify log entries.

use credibil_did::webvh::{self, CreateBuilder, Witness, WitnessWeight};
use credibil_did::{DocumentBuilder, KeyId, Service, VerificationMethod};
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Create a minimal document and then verify the proof. Should verify without
// errors.
#[tokio::test]
async fn simple_proof() {
    let signer =
        Keyring::generate(&Vault, "utd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wvhd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethod::build()
        .key(update_multi.clone())
        .key_id(KeyId::Authorization(id_multi));
    let builder = DocumentBuilder::new().verification_method(vm);

    let result = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .update_keys(vec![update_multi])
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    println!("result log[0]: {:?}", result.log[0]);
    webvh::verify_proofs(&result.log[0]).await.expect("should verify proof");
}

// Create a document with more options and then verify the proof. Should verify
// without errors.
#[tokio::test]
async fn complex_proof() {
    let signer = Keyring::generate(&Vault, "wvhd", "signing", Curve::Ed25519)
        .await
        .expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wvhd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethod::build()
        .key(update_multi.clone())
        .key_id(KeyId::Authorization(id_multi));
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

    webvh::verify_proofs(&result.log[0]).await.expect("should verify proof");
}
