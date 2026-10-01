use super::{display_label, workload_id};
use crate::BrokerError;

#[test]
fn ordinary_japanese_display_labels_are_allowed() {
    let label = "認証情報の稼働状況";
    assert_eq!(display_label(label).expect("safe label"), label);
}

#[test]
fn control_and_bidi_spoofing_characters_are_rejected() {
    for character in [
        '\u{0000}', '\u{0085}', '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}',
        '\u{2066}', '\u{2069}',
    ] {
        let label = format!("safe{character}spoofed");
        assert!(matches!(
            display_label(&label),
            Err(BrokerError::InvalidField("label"))
        ));
    }
}

#[test]
fn workload_identity_uses_a_closed_spiffe_profile() {
    for value in [
        "spiffe://crowsi/local/coela-control",
        "spiffe://crowsi.example/Team_A/worker.01",
        "spiffe://crowsi/-/_",
    ] {
        assert_eq!(workload_id(value).expect("SPIFFE workload"), value);
    }
    for invalid in [
        "workload-coela",
        "SPIFFE://crowsi/local/coela-control",
        "spiffe://crowsi//coela-control",
        "spiffe://crowsi/local/../admin",
        "spiffe://crowsi/local/control?role=admin",
        "spiffe://CROWSI/local/coela-control",
        "spiffe://-crowsi/local/control",
        "spiffe://crowsi/local/~control",
    ] {
        assert!(matches!(
            workload_id(invalid),
            Err(BrokerError::InvalidField("workload"))
        ));
    }
}
