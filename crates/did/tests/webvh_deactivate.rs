//! Tests for the deactivation of a `did:webvh` document and associated log
//! entries.

use credibil_did::webvh::{
    CreateBuilder, DeactivateBuilder, UpdateBuilder, Witness, WitnessWeight,
};
use credibil_did::{DocumentBuilder, KeyId, Service, VerificationMethod};
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating then deactivating a `did:webvh` document and
// log entries. Should just work without errors.
#[tokio::test]
async fn create_deactivate() {
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

    let create_result = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .update_keys(vec![update_multi])
        .next_key(&next_multi)
        .witness(&witnesses)
        .ttl(60)
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let deactivate_result = DeactivateBuilder::from(&create_result.log)
        .expect("should create builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    // Should have 3 log entries: create, nullify next keys, deactivate.
    assert_eq!(deactivate_result.log.len(), 3);
}

// Test the happy path of updating then deactivating a `did:webvh` document and
// log entries. Should just work without errors.
#[tokio::test]
async fn update_deactivate() {
    let signer =
        Keyring::generate(&Vault, "utd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
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

    let create_result = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .update_keys(vec![update_multi])
        .next_key(&next_multi)
        .witness(&witnesses)
        .ttl(60)
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    // --- Update --------------------------------------------------------------

    let doc = create_result.document.clone();

    // Rotate the signing key.
    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes()).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethod::build()
        .key(new_update_multi.clone())
        .key_id(KeyId::Authorization(id_multi));

    // Add another reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let builder =
        DocumentBuilder::from(doc).verification_method(vm).authentication(auth_vm.clone().id);

    // Create an update log signer and skip witness verification of existing log.
    let update_result = UpdateBuilder::new()
        .document(builder)
        .log_entries(create_result.log)
        .rotate_keys(&vec![new_update_multi], &vec![new_next_multi])
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    // --- Deactivate ----------------------------------------------------------

    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let new_update_keys = vec![new_update_multi.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes()).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let new_next_keys = vec![new_next_multi.clone()];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();

    let deactivate_result = DeactivateBuilder::from(&update_result.log_entries)
        .expect("should create builder")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    // Should have 4 log entries: create, update, nullify next keys, deactivate.
    assert_eq!(deactivate_result.log.len(), 4);
}
