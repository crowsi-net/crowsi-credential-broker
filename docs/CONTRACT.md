# Credential boundary contract

Consumers identify a credential with `SecretRef`; they do not know its storage key or value.
The scope binds the reference to a tenant, service, purpose, and audience. A lease additionally
binds one exact host, expires within five minutes, and can be used once.
Issuance and consumption also require the same exact subject, device, workload,
grant, resource, action, and proof-key binding. No unbound production API is
exported.
It also captures the opaque credential revision. If the active revision changes before
consumption, the storage contract returns `CredentialChanged` rather than the new value.

`crowsi://credentials/status/v1` is the cross-repository UI contract. It is metadata-only:
`external_actions` and `contains_secret_values` are fixed to `false`, and its schema rejects
unknown fields. Times are Unix seconds in the inclusive range `0..=253_402_300_799`
(through year 9999). `scope` contains only `tenant`, `service`, and
`audience`; `purpose` is a credential-level field.

The Rust trait is the internal storage port. Its `metadata` method never returns secret material
and is used for lease issuance. A single-envelope backend may internally decode the complete
record to verify integrity, but must zeroize the material before returning metadata. `get` returns
material only when a lease is consumed. `MemoryStore` is only a test/sample backend.
`PlatformCustodyStore` is the local production adapter. It consumes the canonical
`crowsi://platform-custody/runtime/v1` document and delegates user-bound protection to the pinned
provider helper. Another custody adapter can be added without changing broker policy. Revision
restore constructors remain crate-private so external callers cannot bind new material to an old
revision.

Credential enrollment is a separate authenticated IPC operation. The embedding
application first runs its authorization handshake on a Unix stream. Its
`AuthorizationVerifier` receives that same mutable stream and returns verified
subject, device, workload, reservation, resource, action, request-body digest,
and lease binding claims. There is no default verifier. The service then reads
one closed JSON request frame and exactly one opaque secret frame. Each frame
uses a 4-byte big-endian length and is limited to 65,536 bytes. The client must
half-close its write side; missing, partial, extra, and trailing frames fail
closed.

The request body digest binds the complete normalized request, including the
secret digest and credential purpose/reference. A separate resource digest
binds the same canonical credential reference. The service writes the complete
entry, rereads and compares metadata, and only then sends a metadata-only
receipt. The standalone `crowsi-credential` binary cannot bypass this
handshake; it exits with `authenticated-ipc-adapter-required`.

The broker owns a monotonic clock anchored to Unix time. A test can inject another `Clock`, but an
access request cannot submit its own timestamp.

`put` must assign a fresh revision when material changes and must reject reuse of an active
revision. `get(reference, expected_revision)` must atomically return that revision or fail closed.
The platform adapter stores metadata, policy, revision, and secret in one versioned custody envelope and
confirms the revision by reading the entry back after replacement. A partial envelope or a
concurrent overwrite is rejected; no secondary entry can remain orphaned.

Ready UI state is produced only by `CredentialStatus::ready_from_store`, after the referenced
store validates one complete material-bearing record and returns its metadata. The status document
intentionally omits the internal revision. `expired`, `revoked`, and `unavailable` are schema
reservations only until evidence-backed factories are added.

A status document contains at most 1,024 credentials, and one credential contains at most 64
finding codes. Rust constructors and the JSON Schema use the same limits so UI guards can reject
oversized external payloads before rendering. Credential IDs must be unique. Finding codes are
lowercase identifiers matching `[a-z0-9._-]` and are limited to 128 characters.

`contains_secret_values: false` is an authenticated producer assertion, not content
classification. The projection producer must ensure caller-supplied labels, provider names,
store kinds, and finding identifiers are non-secret before constructing the document.
Display labels permit ordinary Unicode, including Japanese, but reject C0/C1 controls and Unicode
bidi controls U+061C, U+200E–U+200F, U+202A–U+202E, and U+2066–U+2069.
