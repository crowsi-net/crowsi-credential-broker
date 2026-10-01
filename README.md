# Crowsi Credential Broker

An independent Rust boundary for local credential custody. It gives workloads opaque references
and short-lived, one-use leases while keeping secret values out of repositories and UI payloads.

## Included

- validated `SecretRef` scope: tenant, service, purpose, and audience;
- exact-host authorization, revision-pinned lease TTL, one-use consumption, and revocation;
- zeroizing, non-`Debug` secret values;
- a fail-closed `CredentialStore` port, in-memory sample backend, and platform custody adapter;
- a bounded, authenticated local IPC enrollment service and matching client codec;
- metadata-only audit receipts and `crowsi://credentials/status/v1` UI documents.

## Verify and run

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
cargo run --locked --offline --bin crowsi-credential-demo
```

Bare `cargo run --locked --offline` selects the production
`crowsi-credential` binary and fails closed until authenticated IPC is
configured. The in-memory `ready` sample is available only through the
explicitly named demo binary above.

The demo creates random bytes in memory, exercises a lease, and prints only the status contract.
It never reads or writes a real credential.

The default API exposes only `issue_bound` and `consume_bound`; there is no
unbound compatibility path. A lease cannot be rebound to another subject,
device, workload, grant, resource, action, or proof key. This is a breaking
change for prototypes that used `issue` or `consume`: they must supply an
authenticated `LeaseBinding`. `revoke_matching`
supports incident-time revocation by subject, device, workload, or grant
without exposing secret values.

`PlatformCustodyStore` loads the canonical owner-only custody runtime document and pins the
Windows DPAPI user helper by SHA-256. Provider failure returns an error; the adapter never falls
back to a repository file, environment variable, Linux Secret Service, or plaintext database.
The adapter stores metadata, revision, host policy, and secret material in one versioned
custody envelope. One update therefore cannot expose a mixed metadata/secret state, and a
post-write read verifies that the requested revision remains active. All temporary strings that
contain the envelope or encoded secret are zeroized. The broker owns its monotonic clock; callers
cannot supply an earlier timestamp to extend a lease. It purges expired leases during issuance
and refuses to exceed 1,024 active leases.

Credential enrollment is available only after an external
`AuthorizationVerifier` authenticates the peer on the same Unix stream. The
IPC request is closed JSON metadata followed by exactly one opaque secret
frame. Both frames are 4-byte big-endian length-prefixed and limited to 64
KiB. The client half-closes its write side, so partial, extra, or trailing
frames fail closed. The service stores the credential and rereads its metadata
before returning a metadata-only receipt.

The `crowsi-credential` executable deliberately exits with
`authenticated-ipc-adapter-required`. It never opens platform custody directly:
a production composition must supply an authenticated verifier and own the
listener lifecycle. This crate supplies the reusable service and client codec,
not permissive authority or a plaintext fallback.

`CredentialStatus::ready_from_store` is the only ready-status factory. It requires validated
metadata from a complete stored envelope; callers cannot construct a ready status directly.
`expired`, `revoked`, and `unavailable` remain reserved until evidence-backed factories exist.
Status generation rejects more than 1,024 credentials; the schema also limits finding codes to 64.
The `contains_secret_values: false` field is an assertion by a trusted projection producer, not a
secret scanner. Caller-supplied labels and provider metadata must already be classified public.

See [SECURITY.md](SECURITY.md) before integration and [docs/CONTRACT.md](docs/CONTRACT.md) for the
cross-repository contract.
