# Credibil Decentralized Identifier (DID) Tools

This crate provides a set of tools and utilities for working with the subset of 
[Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/) used in
 `credibil-vc` and `credibil-dwn`.

> [!CAUTION] This crate is not a generalized DID library and is not intended for
direct use.

## Supported Methods

The crate supports:

- [did:key](https://w3c-ccg.github.io/did-method-key/)
- [did:web](https://w3c-ccg.github.io/did-method-web/)
- [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md/)
- [did:webvh](https://identity.foundation/didwebvh/next/)

with plans to support [did:dht](https://did-dht.com/) in the near future.

## Usage

At this point, the library supports basic DID resolution and document creation. 

While we plan to add support for publishing `did:web`, `did:webvh` and `did:dht`
documents, it will be just that: support. The end-to-end process of publishing
requires additional infrastructure and is out of scope for this library.
