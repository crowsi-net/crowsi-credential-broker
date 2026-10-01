use crowsi_credential_broker::{
    BrokerError, CREDENTIAL_STATUS_SCHEMA, CredentialEntry, CredentialStatus,
    CredentialStatusDocument, CredentialStore, MAX_FINDING_CODES, MAX_STATUS_CREDENTIALS,
    MAX_UNIX_SECONDS, MemoryStore, SecretRef, SecretScope, SecretValue,
};

#[test]
fn status_contract_contains_metadata_only() {
    let reference = SecretRef::new(
        "github-app",
        SecretScope::new("tenant-a", "automation", "repository-read", "zixcel")
            .expect("valid scope"),
    )
    .expect("valid reference");
    let store = MemoryStore::default();
    store
        .put(
            CredentialEntry::new(
                reference.clone(),
                ["api.example.test".to_owned()],
                SecretValue::new(b"test-only-value".to_vec()).expect("valid test secret"),
            )
            .expect("valid entry"),
        )
        .expect("store available");
    let document = CredentialStatusDocument::new(
        42,
        vec![
            CredentialStatus::ready_from_store(
                &store,
                &reference,
                "GitHub認証",
                "github",
                "windows-dpapi-user",
                42,
            )
            .expect("stored credential is ready"),
        ],
    )
    .expect("within document limit");
    let json = serde_json::to_value(document).expect("serializable");

    assert_eq!(json["schema"], CREDENTIAL_STATUS_SCHEMA);
    assert_eq!(json["credential_count"], 1);
    assert_eq!(json["credentials"][0]["label"], "GitHub認証");
    assert_eq!(json["contains_secret_values"], false);
    assert!(json["credentials"][0].get("secret").is_none());
    assert!(json["credentials"][0].get("token").is_none());
}

#[test]
fn ready_status_requires_store_metadata() {
    let reference = SecretRef::new(
        "missing",
        SecretScope::new("tenant-a", "automation", "repository-read", "zixcel")
            .expect("valid scope"),
    )
    .expect("valid reference");
    assert!(matches!(
        CredentialStatus::ready_from_store(
            &MemoryStore::default(),
            &reference,
            "Missing credential",
            "github",
            "memory",
            42
        ),
        Err(BrokerError::NotFound)
    ));
}

#[test]
fn schema_component_limits_match_rust_validation() {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/credential-reference-v1.schema.json"
    ))
    .expect("valid reference schema");
    let status: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/credential-status-v1.schema.json"))
            .expect("valid status schema");

    assert_eq!(reference["$defs"]["component64"]["maxLength"], 64);
    assert_eq!(
        reference["properties"]["scope"]["properties"]["tenant"]["$ref"],
        "#/$defs/component64"
    );
    assert_eq!(status["$defs"]["component64"]["maxLength"], 64);
    assert_eq!(
        status["$defs"]["scope"]["properties"]["service"]["$ref"],
        "#/$defs/component64"
    );
    assert_eq!(
        status["properties"]["credentials"]["maxItems"],
        MAX_STATUS_CREDENTIALS
    );
    assert_eq!(status["properties"]["credentials"]["uniqueItems"], true);
    assert_eq!(
        status["properties"]["credential_count"]["maximum"],
        MAX_STATUS_CREDENTIALS
    );
    assert_eq!(
        status["$defs"]["credential"]["properties"]["finding_codes"]["maxItems"],
        MAX_FINDING_CODES
    );
    assert_eq!(
        status["$defs"]["credential"]["properties"]["finding_codes"]["items"]["maxLength"],
        128
    );
    assert_eq!(
        status["properties"]["generated_at"]["maximum"],
        MAX_UNIX_SECONDS
    );
    for field in ["checked_at", "expires_at", "rotation_due_at"] {
        assert_eq!(
            status["$defs"]["credential"]["properties"][field]["maximum"],
            MAX_UNIX_SECONDS
        );
    }
    let label_pattern = status["$defs"]["credential"]["properties"]["label"]["pattern"]
        .as_str()
        .expect("label pattern");
    assert!(label_pattern.contains("\\u0000-\\u001f"));
    assert!(label_pattern.contains("\\u202a-\\u202e"));
    assert!(label_pattern.contains("\\u2066-\\u2069"));
}
