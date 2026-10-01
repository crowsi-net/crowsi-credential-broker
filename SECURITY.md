# Security policy

## Invariants

- Repositories, SQLite databases, logs, and audit receipts must never contain secret values or
  lease tokens. Status types have no secret field, but caller-supplied labels and provider
  metadata must be classified non-secret by an authenticated, trusted projection producer.
- Callers receive a one-use, audience-and-host-bound lease with a maximum five-minute lifetime.
- A lease is pinned to the credential revision observed at issuance. Rotation makes existing
  leases fail closed; a store must never replace material under an existing revision.
- Every lease binds subject, device, workload, grant, resource, action, and proof-key references.
  The default crate contains no unbound issuance or consumption API.
- `LeaseBinding::new` validates a binding; it does not authenticate its claims.
  The IPC enrollment service requires an `AuthorizationVerifier` to derive
  identity, device, workload, and binding values from the same Unix stream.
- Subject, device, workload, and grant selectors can revoke all matching active bound leases.
- Expired and revoked leases are purged during issuance. The broker refuses issuance at 1,024
  active leases.
- Invalid scope, unavailable storage, poisoned locks, unknown leases, and entropy failures deny
  access.
- The platform custody adapter has no plaintext-file or Linux Secret Service fallback.
- `SecretValue` deliberately has no `Debug` implementation and zeroizes its allocation on drop.

## Deployment

Run the broker under a dedicated OS identity and expose it only through the
authenticated local IPC enrollment service. Its framing is bounded and
deadline-controlled, but the embedding application remains responsible for
peer attestation, authorization policy, listener ownership and permissions,
rate limiting, key rotation, and managed-vault adapters. No verifier is
provided by default. The standalone CLI fails closed rather than opening a
platform custody without that external authorization handshake.

The platform adapter stores metadata, revision, policy, and secret in one custody envelope. The
entry is replaced as one unit, then read back and checked against the requested revision.
Malformed, partial, stale, or concurrently overwritten envelopes fail closed, and no secondary
secret entry can become orphaned. Every plaintext envelope and encoded secret string is wrapped
in zeroizing storage. Backend implementations of `CredentialStore` must preserve the same
complete-envelope and revision semantics.

The adapter mutex serializes one process only; the provider API has no cross-process compare-and-
swap. A writer reads the complete entry back and fails if another writer displaced its payload
before verification. Deployments with multiple writers must add external writer coordination.

`contains_secret_values: false` is a producer assertion, not content inspection or data-loss
prevention. Never copy credential material into `label`, `provider`, `purpose`, `store_kind`, or
finding-code text.
Display labels reject C0/C1 and Unicode bidirectional-control characters to prevent direction-
based spoofing while preserving ordinary Japanese text.

Never pass a credential through process arguments, environment variables, URLs, telemetry, panic
payloads, or browser storage. Consume it only inside the process performing the authorized call.

## Reporting

Treat unexpected credential disclosure as an incident: revoke the provider credential, stop the
affected broker, retain metadata-only audit evidence, rotate the credential, and notify the
security owner through the private incident channel.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
