//! # Data Integrity Proofs
//!
//! ## VC Data Integrity
//!
//! The Verifiable Credential Data Integrity 1.0 [VC-DATA-INTEGRITY]
//! specification relies on the general structure and defines a set of standard
//! properties describing the details of the proof generation process. The
//! specific details (canonicalization algorithm, hash and/or proof method
//! algorithms, etc.) are defined by separate cryptosuites. The Working Group
//! has defined a number of such cryptosuites as separate specifications, see
//! 4.2.3 Cryptosuites below.
//!
//! The core property, in the general structure, is proof. This property embeds
//! a claim in the Credential, referring to a separate collection of claims
//! (referred to as a Proof Graph) detailing all the claims about the proof
//! itself.
//! 
//! For use of data integrity proofs in Verifiable Credentials, see
//! [`credibil-vc`]("https://github.com/credibil/vc").
//! 
//! ## DID Version Integrity
//! 
//! Some methods for Distributed Identifiers (DIDs) require the use of data
//! integrity proofs.
//! 
//! For use of data integrity proofs in DIDs, see
//! [`credibil-did`]("https://github.com/credibil/did").

pub mod w3c;
