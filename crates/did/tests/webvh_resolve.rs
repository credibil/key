//! Tests for resolving a `did:webvh` log into a DID document.

use credibil_did::webvh::{
    self, CreateBuilder, DeactivateBuilder, UpdateBuilder, Witness, WitnessEntry, WitnessWeight,
};
use credibil_did::{DocumentBuilder, KeyId, Service, VerificationMethod};
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Construct a log with a single entry and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_single() {
    let signer =
        Keyring::generate(&Vault, "wrs", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wrs", "id", Curve::Ed25519).await.expect("should generate");
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

    let witness_proof1 = result.log[0].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 = result.log[0].proof(&witness_2).await.expect("should get witness proof");
    let witness_proofs = vec![WitnessEntry {
        version_id: result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];

    let resolved_doc = webvh::resolve_log(&result.log, Some(&witness_proofs), None)
        .await
        .expect("should resolve log");

    // The resolved document should *almost* match the result of the update
    // except for some of the metadata. So remove the metadata from each and
    // then compare.
    let mut result_doc = result.document;
    result_doc.did_document_metadata = None;

    let mut resolved_doc = resolved_doc;
    resolved_doc.did_document_metadata = None;

    assert_eq!(result_doc, resolved_doc);
}

// Construct a log with multiple entries and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_multiple() {
    let signer =
        Keyring::generate(&Vault, "wrm", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wrm", "id", Curve::Ed25519).await.expect("should generate");
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

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let builder = DocumentBuilder::from(doc.clone())
        .verification_method(vm)
        .authentication(auth_vm.id.clone());

    // Create an update log entry and skip witness verification of existing log.
    let result = UpdateBuilder::new()
        .document(builder)
        .log_entries(create_result.log)
        .rotate_keys(&vec![new_update_multi], &vec![new_next_multi])
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let witness_proof1 =
        result.log_entries[0].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 =
        result.log_entries[0].proof(&witness_2).await.expect("should get witness proof");
    let mut witness_proofs = vec![WitnessEntry {
        version_id: result.log_entries[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];
    let witness_proof1 =
        result.log_entries[1].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 =
        result.log_entries[1].proof(&witness_2).await.expect("should get witness proof");
    witness_proofs.push(WitnessEntry {
        version_id: result.log_entries[1].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    });

    let resolved_doc = webvh::resolve_log(&result.log_entries, Some(&witness_proofs), None)
        .await
        .expect("should resolve log");

    // The resolved document should *almost* match the result of the update
    // except for some of the metadata. So remove the metadata from each and
    // then compare.
    let mut result_doc = result.document.clone();
    result_doc.did_document_metadata = None;
    let mut resolved_doc = resolved_doc.clone();
    resolved_doc.did_document_metadata = None;

    assert_eq!(result_doc, resolved_doc);
}

// Test resolving a deactivated document.
#[tokio::test]
async fn resolve_deactivated() {
    let signer =
        Keyring::generate(&Vault, "wrd", "signing", Curve::Ed25519).await.expect("should generate");
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
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes()).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethod::build()
        .key(update_multi.clone())
        .key_id(KeyId::Authorization(id_multi));

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let builder = DocumentBuilder::from(doc.clone())
        .verification_method(vm)
        .authentication(auth_vm.id.clone());

    // Create an update log entry and skip witness verification of existing log.
    let update_result = UpdateBuilder::new()
        .document(builder)
        .log_entries(create_result.log)
        .rotate_keys(&vec![update_multi], &vec![next_multi])
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    // --- Deactivate ----------------------------------------------------------

    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes()).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let next_keys = vec![next_multi];
    let next_keys: Vec<&str> = next_keys.iter().map(|s| s.as_str()).collect();

    let deactivate_result = DeactivateBuilder::from(&update_result.log_entries)
        .expect("should create builder")
        .rotate_keys(&update_keys, &next_keys)
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    let resolved_doc =
        webvh::resolve_log(&deactivate_result.log, None, None).await.expect("should resolve log");
    assert!(
        resolved_doc
            .did_document_metadata
            .expect("should get metadata")
            .deactivated
            .expect("should get deactivated")
    );
}
