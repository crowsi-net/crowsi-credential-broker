# Using crowsi-credential-broker

Keep credentials in custody and lend their use through a narrowly scoped, one-use lease.

## Before you start

Applications must configure custody and the authorization boundary. Secret values must not be copied into configuration or logs.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Register and resolve opaque credential references.
- Limit credential use to an authorized purpose.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
