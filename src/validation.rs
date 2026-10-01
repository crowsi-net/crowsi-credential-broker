use crate::{BrokerError, Result};
use crowsi_control_contracts::validate_spiffe_workload;

pub(crate) fn component(field: &'static str, value: &str, max: usize) -> Result<String> {
    let valid = !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    valid
        .then(|| value.to_owned())
        .ok_or(BrokerError::InvalidField(field))
}

pub(crate) fn workload_id(value: &str) -> Result<String> {
    validate_spiffe_workload(value)
        .is_ok()
        .then(|| value.to_owned())
        .ok_or(BrokerError::InvalidField("workload"))
}

pub(crate) fn normalize_host(value: &str) -> Result<String> {
    let host = value.to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && !host.contains("..")
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    valid
        .then_some(host)
        .ok_or(BrokerError::InvalidField("host"))
}

pub(crate) fn display_label(value: &str) -> Result<String> {
    let valid = !value.is_empty()
        && value.chars().count() <= 160
        && value
            .chars()
            .all(|character| !character.is_control() && !is_bidi_control(character));
    valid
        .then(|| value.to_owned())
        .ok_or(BrokerError::InvalidField("label"))
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

pub(crate) fn valid_finding_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;
