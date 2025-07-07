//! Tests being able to dereference a resource from a `did:web` document.

use std::str::FromStr;

use credibil_did::web::CreateBuilder;
use credibil_did::{
    self, DocumentBuilder, KeyFormat, KeyId, Resource, Service, Url, VerificationMethod,
};
use credibil_ecc::{Curve, Keyring, Signer};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Create a new `did:web` document and dereference a resource from it.
#[tokio::test]
async fn dereference() {
    let signer =
        Keyring::generate(&Vault, "wd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes()).expect("should convert");

    let vm = VerificationMethod::build().key(jwk.clone()).key_id(KeyId::Index("key-0".to_string()));
    let svc = Service::build()
        .id("whois")
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois");
    let builder = DocumentBuilder::new().verification_method(vm).service(svc);

    let document = CreateBuilder::new("https://credibil.io/issuers/example")
        .document(builder)
        .build()
        .expect("should build document");

    // verify
    let Some(vm_list) = &document.verification_method else {
        panic!("should have a verification method");
    };
    let vm_url = &vm_list.first().expect("should have at least one VM").id;
    let url = Url::from_str(vm_url).expect("should parse DID");

    let resource = credibil_did::resource(&url, &document).expect("should dereference VM");
    let Resource::VerificationMethod(vm) = resource else {
        panic!("should be a verification method");
    };

    let KeyFormat::JsonWebKey { public_key_jwk } = vm.key else {
        panic!("should be a JWK");
    };
    assert_eq!(public_key_jwk.x, jwk.x);
}
