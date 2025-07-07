//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a
//! DID.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use credibil_core::{Kind, OneMany};
use credibil_ecc::{ED25519_CODEC, PublicKey, X25519_CODEC}; // derive_x25519_public};
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::KeyFormat;
use crate::service::{Service, ServiceBuilder};
use crate::verification::{VerificationMethod, VerificationMethodBuilder};

// TODO: set context based on key format:
// - Ed25519VerificationKey2020	https://w3id.org/security/suites/ed25519-2020/v1
// - JsonWebKey2020	https://w3id.org/security/suites/jws-2020/v1
// Perhaps this needs to be an enum with Display impl?
/// Candidate contexts to add to a DID document.
pub const CONTEXT: [&str; 2] = ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"];

/// DID Document
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// The context of the DID document.
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// The DID for a particular DID subject.
    ///
    /// The subject is defined as the entity identified by the DID and described
    /// by the DID document. Anything can be a DID subject: person, group,
    /// organization, physical thing, digital thing, logical thing, etc.
    pub id: String,

    /// A set of URIs that are other identifiers for the subject of the above
    /// DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// One or more strings that conform to the rules DID Syntax. The
    /// corresponding DID document(s) SHOULD contain verification
    /// relationships that explicitly permit the use of certain verification
    /// methods for specific purposes.
    ///
    /// Any verification methods contained in the related DID documents
    /// SHOULD be accepted as authoritative, such that proofs that satisfy those
    /// verification methods are to be considered equivalent to proofs provided
    /// by the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<OneMany<String>>,

    /// A set of services, that express ways of communicating with the DID
    /// subject or related entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// If set, MUST be a set of verification methods for the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// The `authentication` verification relationship is used to specify how
    /// the DID subject is expected to be authenticated, for purposes such
    /// as logging into a website or in any sort of challenge-response
    /// protocol.
    ///
    /// <https://www.w3.org/TR/did-core/#authentication>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Kind<VerificationMethod>>>,

    /// The `assertion_method` verification relationship is used to specify how
    /// the DID subject is expected to express claims, such as for the
    /// purposes of issuing a Verifiable Credential.
    ///
    /// <https://www.w3.org/TR/did-core/#assertion>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<Kind<VerificationMethod>>>,

    /// The `key_agreement` verification relationship is used to specify how an
    /// entity can generate encryption material in order to transmit
    /// confidential information intended for the DID subject, such as for
    /// the purposes of establishing a secure communication channel with the
    /// recipient.
    ///
    /// <https://www.w3.org/TR/did-core/#key-agreement>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_invocation` verification relationship is used to specify
    /// a verification method that might be used by the DID subject to
    /// invoke a cryptographic capability, such as the authorization to
    /// update the DID Document.
    ///
    /// <https://www.w3.org/TR/did-core/#capability-invocation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_delegation` verification relationship is used to specify
    /// a mechanism that might be used by the DID subject to delegate a
    /// cryptographic capability to another party, such as delegating the
    /// authority to access a specific HTTP API to a subordinate.
    ///
    /// <https://www.w3.org/TR/did-core/#capability-delegation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<Kind<VerificationMethod>>>,

    /// If resolution is successful, this MUST be metadata about the DID
    /// document. This typically does not change between invocations of the
    /// resolve and resolveRepresentation functions unless the DID document
    /// changes. If resolution is unsuccessful, this output MUST be an
    /// empty.
    ///
    /// <https://w3c.github.io/did-core/#dfn-diddocumentmetadata>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
}

impl Document {
    /// Retrieve a service by its ID.
    #[must_use]
    pub fn service(&self, id: &str) -> Option<&Service> {
        self.service.as_ref()?.iter().find(|s| s.id == id)
    }

    /// Retrieve a verification method by its ID.
    #[must_use]
    pub fn verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.as_ref()?.iter().find(|vm| vm.id == id)
    }
}

/// DID Document builder.
pub struct DocumentBuilder<D> {
    document: D,
    authentication: Option<Vec<Kind<VerificationMethodBuilder>>>,
    assertion_method: Option<Vec<Kind<VerificationMethodBuilder>>>,
    key_agreement: Option<Vec<Kind<VerificationMethodBuilder>>>,
    capability_invocation: Option<Vec<Kind<VerificationMethodBuilder>>>,
    capability_delegation: Option<Vec<Kind<VerificationMethodBuilder>>>,
    verification_method: Option<Vec<VerificationMethodBuilder>>,
    derive_key_agreement: Option<bool>,
    also_known_as: Option<Vec<String>>,
    controller: Option<OneMany<String>>,
    service: Option<Vec<ServiceBuilder>>,
    context: Option<Vec<Kind<Value>>>,
    metadata: Option<DocumentMetadata>,
}

impl Default for DocumentBuilder<FromScratch> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder does not have a document (can't build).
pub struct FromScratch;

/// Builder has a document (can build).
pub struct FromDocument(Document);

impl DocumentBuilder<FromScratch> {
    /// Creates a new `DocumentBuilder` with the given DID URL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            document: FromScratch,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            verification_method: None,
            derive_key_agreement: None,
            also_known_as: None,
            controller: None,
            service: None,
            context: Some(CONTEXT.iter().map(|ctx| Kind::String((*ctx).to_string())).collect()),
            metadata: None,
        }
    }

    /// Creates a new `DocumentBuilder` from an existing `Document`.
    #[must_use]
    pub const fn from(document: Document) -> DocumentBuilder<FromDocument> {
        DocumentBuilder {
            document: FromDocument(document),
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            verification_method: None,
            derive_key_agreement: None,
            also_known_as: None,
            controller: None,
            service: None,
            context: None,
            metadata: None,
        }
    }
}

impl<D> DocumentBuilder<D> {
    /// Add an also-known-as identifier.
    #[must_use]
    pub fn also_known_as(mut self, aka: impl Into<String>) -> Self {
        self.also_known_as.get_or_insert(vec![]).push(aka.into());
        self
    }

    /// Add a controller.
    ///
    /// Chain to add multiple controllers.
    #[must_use]
    pub fn add_controller(mut self, controller: impl Into<String>) -> Self {
        match self.controller {
            Some(OneMany::One(c)) => {
                self.controller = Some(OneMany::Many(vec![c, controller.into()]));
            }
            Some(OneMany::Many(mut c)) => {
                c.push(controller.into());
                self.controller = Some(OneMany::Many(c));
            }
            None => self.controller = Some(OneMany::One(controller.into())),
        }
        self
    }

    // /// Remove a controller.
    // ///
    // /// # Errors
    // /// Will fail if the controller is not found.
    // pub fn remove_controller(mut self, controller: &str) -> Result<Self> {
    //     match self.doc.controller {
    //         Some(c) => match c {
    //             OneMany::One(cont) => {
    //                 if cont == controller {
    //                     self.doc.controller = None;
    //                 } else {
    //                     bail!("controller not found");
    //                 }
    //             }
    //             OneMany::Many(mut cont) => {
    //                 if let Some(pos) = cont.iter().position(|c| c == controller) {
    //                     cont.remove(pos);
    //                     self.doc.controller = Some(OneMany::Many(cont));
    //                 } else {
    //                     bail!("controller not found");
    //                 }
    //             }
    //         },
    //         None => {
    //             bail!("controller not found");
    //         }
    //     }
    //     Ok(self)
    // }

    /// Add a service endpoint.
    ///
    /// Chain to add multiple service endpoints.
    #[must_use]
    pub fn service(mut self, service: ServiceBuilder) -> Self {
        self.service.get_or_insert(vec![]).push(service);
        self
    }

    // /// Remove a service endpoint.
    // ///
    // /// # Errors
    // /// Will fail if no service with the supplied ID is found.
    // pub fn remove_service(mut self, service_id: &str) -> Result<Self> {
    //     if let Some(services) = &mut self.doc.service {
    //         if let Some(pos) = services.iter().position(|s| s.id == service_id) {
    //             services.remove(pos);
    //         } else {
    //             bail!("service not found");
    //         }
    //     } else {
    //         bail!("service not found");
    //     }
    //     Ok(self)
    // }

    /// Add a context.
    ///
    /// Chain to add multiple contexts.
    #[must_use]
    pub fn context(mut self, context: Kind<Value>) -> Self {
        self.context.get_or_insert(vec![]).push(context);
        self
    }

    // /// Remove a context.
    // ///
    // /// # Errors
    // /// Will fail if the context is not found.
    // pub fn remove_context(mut self, context: &Kind<Value>) -> Result<Self> {
    //     if let Some(pos) = self.doc.context.iter().position(|c| c == context) {
    //         self.doc.context.remove(pos);
    //     } else {
    //         bail!("context not found");
    //     }
    //     Ok(self)
    // }

    /// Add a verification method to the `assertion_method` relationship.
    #[must_use]
    pub fn assertion_method(
        mut self, assertion_method: impl Into<Kind<VerificationMethodBuilder>>,
    ) -> Self {
        self.assertion_method.get_or_insert(vec![]).push(assertion_method.into());
        self
    }

    /// Add a verification method to the `authentication` relationship.
    #[must_use]
    pub fn authentication(
        mut self, authentication: impl Into<Kind<VerificationMethodBuilder>>,
    ) -> Self {
        self.authentication.get_or_insert(vec![]).push(authentication.into());
        self
    }

    /// Add a verification method to the `key_agreement` relationship.
    #[must_use]
    pub fn key_agreement(mut self, key_agreement: VerificationMethodBuilder) -> Self {
        self.key_agreement.get_or_insert(vec![]).push(Kind::Object(key_agreement));
        self
    }

    /// Add a verification method to the `capability_invocation` relationship.
    #[must_use]
    pub fn capability_invocation(
        mut self, capability_invocation: impl Into<Kind<VerificationMethodBuilder>>,
    ) -> Self {
        self.capability_invocation.get_or_insert(vec![]).push(capability_invocation.into());
        self
    }

    /// Add a verification method to the `capability_delegation` relationship.
    #[must_use]
    pub fn capability_delegation(
        mut self, capability_delegation: impl Into<Kind<VerificationMethodBuilder>>,
    ) -> Self {
        self.capability_delegation.get_or_insert(vec![]).push(capability_delegation.into());
        self
    }

    /// Add a verification method to the `key_agreement` relationship.
    #[must_use]
    pub fn verification_method(mut self, builder: VerificationMethodBuilder) -> Self {
        self.verification_method.get_or_insert(vec![]).push(builder);
        self
    }

    // /// Remove the specified verification method.
    // pub fn remove_verification_method(mut self, vm_id: impl Into<String>) -> Self {
    //     self.remove_verification_method.push(vm_id.into());
    //     self
    // }

    /// Create a new `X25519` key agreement verification method from the
    /// `Ed25519` signing key.
    ///
    /// You must pass in the ID of the signing verification method that already
    /// exists in the document being built, so ensure to call
    /// `add_verification_method` with `KeyPurpose::VerificationMethod` before
    /// calling this method.
    ///
    /// NOTE: In general, a signing key should never be used for encryption,
    /// so this method should only be used where the DID method gives you no
    /// choice, such as `did:key`.
    ///
    /// TODO: Consider returning an error if not `did:key`.
    #[must_use]
    pub const fn derive_key_agreement(mut self, derive: bool) -> Self {
        self.derive_key_agreement = Some(derive);
        self
    }

    // /// Retrieve the current `DID` from the builder.
    // ///
    // /// Note that although the `DID` (document identifier) is called for in the
    // /// constructor of this builder, some DID methods may use temporary values
    // /// and replace the DID in the final document. Users of this function should
    // /// be aware of the DID method context in which it is used to determine the
    // /// reliability of the value.
    // #[must_use]
    // pub fn did(&self) -> String {
    //     self.doc.id.clone()
    // }

    /// Set metadata for the document.
    #[must_use]
    pub fn metadata(mut self, metadata: DocumentMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl DocumentBuilder<FromScratch> {
    /// Update metadata with created or updated timestamp and build the DID
    /// Document.
    ///
    /// # Errors
    ///
    /// Will fail if the document is missing required fields or if
    /// verification methods are not properly set up.
    pub(crate) fn build(self, did: impl Into<String>) -> Result<Document> {
        let document = Document {
            id: did.into(),
            ..Document::default()
        };
        self.inner_build(document)
    }
}

impl DocumentBuilder<FromDocument> {
    /// Update metadata with created or updated timestamp and build the DID
    /// Document.
    ///
    /// # Errors
    ///
    /// Will fail if the document is missing required fields or if
    /// verification methods are not properly set up.
    pub(crate) fn build(self) -> Result<Document> {
        let document = self.document.0.clone();
        self.inner_build(document)
    }
}

impl<D> DocumentBuilder<D> {
    fn inner_build(self, mut document: Document) -> Result<Document> {
        let did = document.id.clone();

        // verification methods
        if let Some(builders) = self.verification_method {
            for b in builders {
                let vm = b.build(&document.id)?;
                document.verification_method.get_or_insert(vec![]).push(vm.clone());

                if self.derive_key_agreement.unwrap_or_default() {
                    let multi_key = match vm.key {
                        KeyFormat::Multikey { public_key_multibase } => public_key_multibase,
                        KeyFormat::JsonWebKey { public_key_jwk } => {
                            public_key_jwk.to_multibase()?
                        }
                    };

                    let vm = x25519_key_agreement(&document.id, &multi_key)?;
                    document.key_agreement.get_or_insert(vec![]).push(Kind::Object(vm));
                }
            }
        }

        document.assertion_method = to_vm(&did, self.assertion_method)?;
        document.authentication = to_vm(&did, self.authentication)?;
        document.key_agreement = to_vm(&did, self.key_agreement)?;
        document.capability_invocation = to_vm(&did, self.capability_invocation)?;
        document.capability_delegation = to_vm(&did, self.capability_delegation)?;

        // services
        if let Some(builders) = self.service {
            for b in builders {
                let svc = b.build(&document.id)?;
                document.service.get_or_insert(vec![]).push(svc);
            }
        }

        document.also_known_as = self.also_known_as;
        document.controller = self.controller;

        let mut metadata = self.metadata.unwrap_or_default();
        metadata.updated = Some(chrono::Utc::now());
        document.did_document_metadata = Some(metadata);

        if let Some(context) = self.context {
            document.context.extend(context);
        }

        Ok(document)
    }
}

fn to_vm(
    did: &str, vms: Option<Vec<Kind<VerificationMethodBuilder>>>,
) -> Result<Option<Vec<Kind<VerificationMethod>>>> {
    let Some(verification_methods) = vms else {
        return Ok(None);
    };

    let mut fixed = vec![];
    for vm in verification_methods {
        match vm {
            Kind::Object(b) => {
                fixed.push(Kind::Object(b.build(did)?));
            }
            Kind::String(key_id) => {
                fixed.push(Kind::String(format!("{did}#{key_id}")));
            }
        }
    }

    Ok(Some(fixed))
}

// Derive and X25519-based Key Agreement from an Ed25519 public key.
fn x25519_key_agreement(did: impl Into<String>, ed25519_key: &str) -> Result<VerificationMethod> {
    let (base, multi_bytes) = multibase::decode(ed25519_key)
        .map_err(|e| anyhow!("failed to decode multibase key: {e}"))?;
    if base != Base::Base58Btc {
        return Err(anyhow!("multibase base is not Base58Btc"));
    }
    if multi_bytes[0..ED25519_CODEC.len()] != ED25519_CODEC {
        return Err(anyhow!("key is not an Ed25519 key"));
    }

    let key_bytes = multi_bytes[ED25519_CODEC.len()..].to_vec();
    let pub_key = PublicKey::from_slice(&key_bytes)?;
    let x25519_key = pub_key.derive_x25519()?;

    // base58B encode the raw key
    let mut multi_bytes = vec![];
    multi_bytes.extend_from_slice(&X25519_CODEC);
    multi_bytes.extend_from_slice(&x25519_key.to_bytes());
    let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

    VerificationMethod::build().key(multikey).build(did)
}

// let mut found = false;
// if let Some(auths) = &mut self.doc.authentication {
//     if let Some(pos) = auths.iter().position(|vm| match vm {
//         Kind::Object(vm) => vm.id == vm_id,
//         Kind::String(id) => id == vm_id,
//     }) {
//         auths.remove(pos);
//         found = true;
//     }
// }
// if let Some(asserts) = &mut self.doc.assertion_method {
//     if let Some(pos) = asserts.iter().position(|vm| match vm {
//         Kind::Object(vm) => vm.id == vm_id,
//         Kind::String(id) => id == vm_id,
//     }) {
//         asserts.remove(pos);
//         found = true;
//     }
// }
// if let Some(kas) = &mut self.doc.key_agreement {
//     if let Some(pos) = kas.iter().position(|vm| match vm {
//         Kind::Object(vm) => vm.id == vm_id,
//         Kind::String(id) => id == vm_id,
//     }) {
//         kas.remove(pos);
//         found = true;
//     }
// }
// if let Some(caps) = &mut self.doc.capability_invocation {
//     if let Some(pos) = caps.iter().position(|vm| match vm {
//         Kind::Object(vm) => vm.id == vm_id,
//         Kind::String(id) => id == vm_id,
//     }) {
//         caps.remove(pos);
//         found = true;
//     }
// }
// if let Some(caps) = &mut self.doc.capability_delegation {
//     if let Some(pos) = caps.iter().position(|vm| match vm {
//         Kind::Object(vm) => vm.id == vm_id,
//         Kind::String(id) => id == vm_id,
//     }) {
//         caps.remove(pos);
//         found = true;
//     }
// }
// if let Some(vms) = &mut self.doc.verification_method {
//     if let Some(pos) = vms.iter().position(|vm| vm.id == vm_id) {
//         vms.remove(pos);
//         found = true;
//     }
// }
// if !found {
//     bail!("verification method not found");
// }

/// DID document metadata. This typically does not change unless the DID
/// document changes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct DocumentMetadata {
    /// Timestamp of the Create operation.
    /// An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    pub created: DateTime<Utc>,

    /// Timestamp of the last Update operation. Omitted if an Update operation
    /// has never been performed. May be the same value as the `created`
    /// property when the difference between the two timestamps is less than
    /// one second. An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,

    /// MUST be set to true if the DID has been deactivated. Optional if the DID
    /// has not been deactivated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// May be set if the document version is not the latest. Indicates the
    /// timestamp of the next Update operation as an XMLSCHEMA11-2
    /// (RFC3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<DateTime<Utc>>,

    /// Used to indicate the version of the last Update operation. SHOULD be
    /// set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// MAY be set if the document version is not the latest. It indicates the
    /// version of the next Update operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<String>,

    /// Used when a DID method needs to define different forms of a DID that are
    /// logically equivalent. For example, when a DID takes one form prior to
    /// registration in a verifiable data registry and another form after such
    /// registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equivalent_id: Option<Vec<String>>,

    /// Identical to the `equivalent_id` property except that it is a single
    /// value AND the DID is the canonical ID for the DID subject within the
    /// containing DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,

    /// Additional metadata specified by the DID method.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional: Option<HashMap<String, Value>>,
}

/// Builder for DID document metadata.
#[derive(Clone, Debug, Default)]
pub struct DocumentMetadataBuilder {
    md: DocumentMetadata,
}

impl DocumentMetadataBuilder {
    /// Creates a new `DocumentMetadataBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            md: DocumentMetadata::default(),
        }
    }

    /// Creates a new `DocumentMetadataBuilder` from an existing
    /// `DocumentMetadata`.
    #[must_use]
    pub fn from(md: &DocumentMetadata) -> Self {
        Self { md: md.clone() }
    }

    /// Set the created timestamp.
    #[must_use]
    pub const fn created(mut self, created: &DateTime<Utc>) -> Self {
        self.md.created = *created;
        self
    }

    /// Set the updated timestamp.
    #[must_use]
    pub const fn updated(mut self, updated: &DateTime<Utc>) -> Self {
        self.md.updated = Some(*updated);
        self
    }

    /// Set the deactivated flag.
    #[must_use]
    pub const fn deactivated(mut self, deactivated: bool) -> Self {
        self.md.deactivated = Some(deactivated);
        self
    }

    /// Set the next update timestamp.
    #[must_use]
    pub const fn next_update(mut self, next_update: &DateTime<Utc>) -> Self {
        self.md.next_update = Some(*next_update);
        self
    }

    /// Set the version ID.
    #[must_use]
    pub fn version_id(mut self, version_id: &str) -> Self {
        self.md.version_id = Some(version_id.into());
        self
    }

    /// Set the next version ID.
    #[must_use]
    pub fn next_version_id(mut self, next_version_id: &str) -> Self {
        self.md.next_version_id = Some(next_version_id.into());
        self
    }

    /// Set the equivalent ID.
    #[must_use]
    pub fn equivalent_id(mut self, equivalent_id: &[&str]) -> Self {
        self.md.equivalent_id = Some(equivalent_id.iter().map(|s| (*s).to_string()).collect());
        self
    }

    /// Set the canonical ID.
    #[must_use]
    pub fn canonical_id(mut self, canonical_id: &str) -> Self {
        self.md.canonical_id = Some(canonical_id.into());
        self
    }

    /// Set an addition field
    #[must_use]
    pub fn additional(mut self, key: &str, value: impl Into<Value>) -> Self {
        if let Some(additional) = &mut self.md.additional {
            additional.insert(key.into(), value.into());
        } else {
            let mut additional = HashMap::new();
            additional.insert(key.into(), value.into());
            self.md.additional = Some(additional);
        }
        self
    }

    /// Build the metadata.
    #[must_use]
    pub fn build(self) -> DocumentMetadata {
        self.md
    }
}
