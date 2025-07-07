# `did:webvh` DID Method Example

This is a simple example of implementing a `did:webvh` DID method service using [Credibil's](https://credibil.io) DID library, the `credibil-did` crate for Rust.

It is a minimal implementation using very simple DID documents and runs as a web service.

## Getting Started

The example exists in a Cargo workspace so clone the whole [`credibil-did` repository](https://github.com/credibil/did) and start the self-contained web service from the repository root:

```shell
cargo run -p webvh
```

Then using curl or Postman you can explore creating, updating, resolving and deactivating a DID document:

### Create

To create a did document:

```shell
curl --location 'http://localhost:8080/create' \
--header 'Content-Type: application/json' \
--data '{}'
```

### Update

The update endpoint will rotate keys and add another verification method to the DID document. See the `UpdateRequest` struct in the `update.rs` file: you can define a key purpose for the verification method to add. If you leave this blank a general purpose verification method is added anyway.

```shell
curl --location 'http://localhost:8080/update' \
--header 'Content-Type: application/json' \
--data '{"add": "Authentication"}'
```

### Deactivate

To deactivate a DID document:

```shell
curl --location --request POST 'http://localhost:8080/deactivate'
```

### Resolve

To resolve the latest DID document make a `GET` request to the `.well-known/did.json` endpoint.

```shell
curl --location 'http://localhost:8080/.well-known/did.json'
```

You can also request a specific DID document from within the history by supplying the version ID. You can experiment with this by using the `create`, `update` and `deactivate` endpoints to populate a log of updates, then use a query parameter to target the version you want.

```shell
curl --location 'http://localhost:8080/.well-known/did.json?versionId=2-zhWiW3YwiSaUFfGkUZDg1GigfSozhoKe7Vdm5pXe1vE3'
```

### Read JSON Log

The read endpoint will `GET` the JSON log file (`did.jsonl`). You can call this after the other operations to see their effect.

```shell
curl --location 'http://localhost:8080/.well-known/did.jsonl'
```

Note that the returned result for this example is a newline-delimited set of JSON objects. There is no standard MIME-type for this. See [jsonlines.org](https://jsonlines.org/).
