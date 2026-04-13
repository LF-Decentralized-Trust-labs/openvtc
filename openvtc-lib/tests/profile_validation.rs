use openvtc::config::{
    MIN_PASSPHRASE_LENGTH, UnlockCode, public_config::validate_profile_name, validate_passphrase,
};

// --- Profile name validation ---

#[test]
fn valid_profile_names() {
    assert!(validate_profile_name("default").is_ok());
    assert!(validate_profile_name("my-profile").is_ok());
    assert!(validate_profile_name("my_profile").is_ok());
    assert!(validate_profile_name("Profile123").is_ok());
    assert!(validate_profile_name("a").is_ok());
}

#[test]
fn empty_profile_name_rejected() {
    assert!(validate_profile_name("").is_err());
}

#[test]
fn profile_name_with_spaces_rejected() {
    assert!(validate_profile_name("my profile").is_err());
}

#[test]
fn profile_name_with_special_chars_rejected() {
    assert!(validate_profile_name("my.profile").is_err());
    assert!(validate_profile_name("my/profile").is_err());
    assert!(validate_profile_name("my@profile").is_err());
    assert!(validate_profile_name("name!").is_err());
}

// --- Passphrase validation ---

#[test]
fn passphrase_at_minimum_length_accepted() {
    let pass = "a".repeat(MIN_PASSPHRASE_LENGTH);
    assert!(validate_passphrase(&pass).is_ok());
}

#[test]
fn passphrase_below_minimum_length_rejected() {
    let pass = "a".repeat(MIN_PASSPHRASE_LENGTH - 1);
    assert!(validate_passphrase(&pass).is_err());
}

#[test]
fn empty_passphrase_rejected() {
    assert!(validate_passphrase("").is_err());
}

#[test]
fn long_passphrase_accepted() {
    let pass = "x".repeat(256);
    assert!(validate_passphrase(&pass).is_ok());
}

// --- UnlockCode::from_string ---

#[test]
fn unlock_code_from_valid_string() {
    assert!(UnlockCode::from_string("secure-passphrase-123").is_ok());
}

#[test]
fn unlock_code_from_short_string_rejected() {
    assert!(UnlockCode::from_string("short").is_err());
}

#[test]
fn unlock_code_from_empty_string_rejected() {
    assert!(UnlockCode::from_string("").is_err());
}
