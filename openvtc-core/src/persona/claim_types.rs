//! What a claim type says about showing its own value — a **vendored copy** of
//! the masking half of the persona claim-type registry.
//!
//! Source of truth:
//! `dtgwg-trust-tasks-tf/specs/persona/_shared/0.1/claim-types.json`, with the
//! reasoning beside it in `CLAIM-TYPES.md`. This module carries two of that
//! file's four per-type members — `sensitivity` and `mask` — because those are
//! the two a pane needs to decide how to paint a row. `release` and `oidc` are
//! deliberately absent: nothing here releases anything, and a copy of a table
//! nobody reads is a copy that goes stale unnoticed.
//!
//! It is vendored because **the agent does not serve this table.** There is no
//! `persona/claim-types/list` task — the registry's own §6 lists adding one as
//! an open question — so a client that wants a default has to ship it. Re-sync
//! by hand against the file named above when the registry moves; the whole of
//! the copy is [`TABLE`] plus [`UNREGISTERED`].
//!
//! # This is not a security control, and it must not be described as one
//!
//! Masking here happens *after* the value has been fetched, decrypted by the
//! agent, sent over DIDComm and parked in this process's memory. Everything
//! that could read it before still can. What it defends against is a person
//! reading the terminal over a shoulder, and a screenshot or a screen share
//! carrying a card number to an audience that was never asked.
//!
//! The control that would actually matter is on the read path — an
//! `includeSensitive` flag on `persona/attribute/list`, so a listing that did
//! not ask for sensitive values is never *sent* them. It does not exist:
//! `persona_attribute_list` takes `include_values` and nothing finer. The
//! registry says the same thing in §3.1 — "masking a value already fetched is
//! theatre; the control that matters is on the read path" — and the mask is
//! what makes that missing control visible rather than a substitute for it.
//!
//! # Only `sensitivity` decides whether to mask
//!
//! `mask` says *how* a value is reduced, not *whether* it is. A `normal` type
//! carrying a style (`email.work` is `normal` + `emailLocal`) is shown in full
//! to its own holder; the style is there for the surfaces that reduce a value
//! for someone else. Reading the style as the trigger would mask a work email
//! address in a holder's own list, which teaches the reveal key as a reflex —
//! and a reveal pressed by reflex protects nothing.

/// How carefully a value is shown **to its own holder**.
///
/// Not linkability, and not what it takes to release the value — the registry's
/// §3 keeps those three apart because a mechanism that reads one as a proxy for
/// another hides the wrong things and warns about the wrong things. A payment
/// card is highly sensitive and barely linkable; a nickname can be the reverse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sensitivity {
    /// Shown as it is held.
    #[default]
    Normal,
    /// Masked until the holder asks for this one value.
    High,
}

/// How a value is reduced when it is shown masked. The styles, and their
/// wording, are `claim-types.json`'s `maskStyles`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaskStyle {
    /// Shown in full. The value is not one a shoulder can steal.
    #[default]
    None,
    /// Final two characters shown; everything before them replaced.
    Last2,
    /// Final four characters shown; everything before them replaced.
    Last4,
    /// First character of the local part, then the domain in full.
    EmailLocal,
    /// No characters shown.
    Full,
}

/// The bullet a replaced character is drawn as. `*` reads as a footnote and `x`
/// as data; `•` is neither, and is what every other masked field in the
/// ecosystem uses.
const BULLET: char = '•';

/// Width of a fully masked value.
///
/// Fixed, rather than one bullet per character held: the length of a passport
/// number or a date of birth is itself a hint, and a mask that leaks it has
/// given away the one thing the style exists to withhold. It also keeps a
/// column stable while the holder pages down a list.
const FULL_MASK_WIDTH: usize = 8;

impl MaskStyle {
    /// Reduce `text` to the form this style shows.
    ///
    /// Every style falls back to [`Full`](MaskStyle::Full) rather than to the
    /// clear text when the value does not have the shape the style assumes —
    /// a `last4` over three characters, an `emailLocal` over something with no
    /// `@`. The alternative is a mask that silently stops masking on exactly
    /// the values it was misapplied to.
    #[must_use]
    pub fn apply(self, text: &str) -> String {
        let full = || BULLET.to_string().repeat(FULL_MASK_WIDTH);
        match self {
            Self::None => text.to_string(),
            Self::Full => full(),
            Self::Last2 | Self::Last4 => {
                let keep = if self == Self::Last2 { 2 } else { 4 };
                let chars: Vec<char> = text.chars().collect();
                // Strictly longer, not "at least": a four-character value under
                // `last4` would be shown whole by a rule that says it is masked.
                if chars.len() <= keep {
                    return full();
                }
                let tail: String = chars[chars.len() - keep..].iter().collect();
                format!("{}{tail}", BULLET.to_string().repeat(chars.len() - keep))
            }
            Self::EmailLocal => match text.split_once('@') {
                // The domain is what makes an address recognisable to its
                // owner; the local part is what makes it usable to anyone else.
                Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
                    let first = local.chars().next().unwrap_or(BULLET);
                    format!("{first}{}@{domain}", BULLET.to_string().repeat(3))
                }
                _ => full(),
            },
        }
    }

    /// Whether showing a value through this style actually withholds anything.
    #[must_use]
    pub fn hides_anything(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// What one claim type says about showing its value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClaimTypeDefaults {
    pub sensitivity: Sensitivity,
    pub mask: MaskStyle,
}

impl ClaimTypeDefaults {
    /// Whether a value of this type is shown masked by default.
    #[must_use]
    pub fn masks_by_default(self) -> bool {
        self.sensitivity == Sensitivity::High && self.mask.hides_anything()
    }

    /// The value as this type shows it — masked when the type asks for it.
    #[must_use]
    pub fn render(self, text: &str) -> String {
        if self.masks_by_default() {
            self.mask.apply(text)
        } else {
            text.to_string()
        }
    }
}

/// What a type this registry has never seen resolves to.
///
/// The conservative answer, and the registry's §4 rule 3: a vocabulary nobody
/// has reasoned about is exactly the one nothing is known about, and an unknown
/// value rendered in the clear is a decision nobody made. It applies to
/// unregistered tokens and to the open `x:` namespace alike — the registry
/// gives both the same defaults.
pub const UNREGISTERED: ClaimTypeDefaults = ClaimTypeDefaults {
    sensitivity: Sensitivity::High,
    mask: MaskStyle::Full,
};

/// The vendored table, in `claim-types.json`'s order so the two diff against
/// each other by eye.
const TABLE: &[(&str, Sensitivity, MaskStyle)] = &[
    ("name.legal", Sensitivity::Normal, MaskStyle::None),
    ("name.given", Sensitivity::Normal, MaskStyle::None),
    ("name.family", Sensitivity::Normal, MaskStyle::None),
    ("name.display", Sensitivity::Normal, MaskStyle::None),
    // A former name is the one a holder most often keeps in order to answer a
    // question once and never show again.
    ("name.previous", Sensitivity::High, MaskStyle::Full),
    ("person.birthDate", Sensitivity::High, MaskStyle::Full),
    ("person.pronouns", Sensitivity::Normal, MaskStyle::None),
    ("person.locale", Sensitivity::Normal, MaskStyle::None),
    ("email.personal", Sensitivity::Normal, MaskStyle::EmailLocal),
    ("email.work", Sensitivity::Normal, MaskStyle::EmailLocal),
    // High because a mobile number is both a strong join key and an
    // authentication factor: its harm is account takeover, not embarrassment.
    ("phone.mobile", Sensitivity::High, MaskStyle::Last2),
    ("phone.landline", Sensitivity::High, MaskStyle::Last2),
    ("address.postal", Sensitivity::High, MaskStyle::Full),
    ("address.country", Sensitivity::Normal, MaskStyle::None),
    ("gov.id.passport", Sensitivity::High, MaskStyle::Last4),
    ("gov.id.driverLicence", Sensitivity::High, MaskStyle::Last4),
    ("gov.id.national", Sensitivity::High, MaskStyle::Last4),
    ("gov.taxId", Sensitivity::High, MaskStyle::Last4),
    ("payment.card", Sensitivity::High, MaskStyle::Last4),
    ("payment.cardExpiry", Sensitivity::High, MaskStyle::Full),
    ("payment.iban", Sensitivity::High, MaskStyle::Last4),
    ("payment.accountNumber", Sensitivity::High, MaskStyle::Last4),
    ("account.handle", Sensitivity::Normal, MaskStyle::None),
    ("url.homepage", Sensitivity::Normal, MaskStyle::None),
    ("org.name", Sensitivity::Normal, MaskStyle::None),
    ("org.role", Sensitivity::Normal, MaskStyle::None),
];

/// Resolve a claim type to how its value is shown.
///
/// The match is exact. A token is not resolved by walking up its family —
/// `payment.giftCard` is unregistered, not "a `payment.*`" — because the
/// families are a naming convention rather than a scope, and inheriting from a
/// prefix would let a *new* `x:payment.…` inherit a registered family's
/// answer. Unregistered is already the conservative one; there is nothing a
/// prefix walk could add but a way to be wrong.
#[must_use]
pub fn resolve(claim_type: &str) -> ClaimTypeDefaults {
    TABLE
        .iter()
        .find(|(token, _, _)| *token == claim_type)
        .map_or(UNREGISTERED, |(_, sensitivity, mask)| ClaimTypeDefaults {
            sensitivity: *sensitivity,
            mask: *mask,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registered types resolve to what the vendored table says, including
    /// the two that are `high` without being `full` — the styles exist so a
    /// holder can still recognise their own card and their own number.
    #[test]
    fn registered_types_resolve_to_their_entry() {
        assert_eq!(resolve("name.legal").sensitivity, Sensitivity::Normal);
        assert_eq!(resolve("payment.card").mask, MaskStyle::Last4);
        assert_eq!(resolve("phone.mobile").mask, MaskStyle::Last2);
        assert!(resolve("gov.id.passport").masks_by_default());
        assert!(!resolve("org.role").masks_by_default());
    }

    /// An unregistered token and an `x:` extension get the conservative answer.
    ///
    /// This is the case the whole default exists for: a build that has never
    /// heard of a vocabulary knows nothing about what it holds, and showing it
    /// in the clear would be a decision nobody made.
    #[test]
    fn an_unknown_type_masks_fully() {
        for token in ["x:employer.badge", "medical.condition", "", "payment"] {
            let resolved = resolve(token);
            assert_eq!(resolved.sensitivity, Sensitivity::High, "{token}");
            assert_eq!(resolved.mask, MaskStyle::Full, "{token}");
        }
    }

    /// A family prefix is not a scope. `payment.giftCard` is a token this build
    /// has never seen, and inheriting `payment.card`'s entry would be a guess
    /// dressed as a lookup.
    #[test]
    fn a_family_prefix_does_not_inherit() {
        assert_eq!(resolve("payment.giftCard"), UNREGISTERED);
        assert_eq!(resolve("x:payment.card"), UNREGISTERED);
    }

    /// `normal` sensitivity is shown whole even when the type names a style —
    /// see the module header. `email.work` is the case in the registry today.
    #[test]
    fn a_normal_type_is_not_masked_by_its_style() {
        let email = resolve("email.work");
        assert_eq!(email.mask, MaskStyle::EmailLocal);
        assert!(!email.masks_by_default());
        assert_eq!(email.render("alice@example.com"), "alice@example.com");
    }

    /// Each style keeps exactly the characters it says it keeps.
    #[test]
    fn each_style_keeps_what_it_says_it_keeps() {
        assert_eq!(MaskStyle::None.apply("Alice"), "Alice");
        assert_eq!(
            MaskStyle::Last4.apply("4242424242424242"),
            "••••••••••••4242"
        );
        assert_eq!(MaskStyle::Last2.apply("+61400123456"), "••••••••••56");
        assert_eq!(
            MaskStyle::EmailLocal.apply("alice@example.com"),
            "a•••@example.com"
        );
        assert_eq!(MaskStyle::Full.apply("1990-01-01"), "••••••••");
    }

    /// A fully masked value is a fixed width, so the mask does not report the
    /// length of what it is hiding.
    #[test]
    fn a_full_mask_does_not_leak_the_length() {
        assert_eq!(
            MaskStyle::Full.apply("1990-01-01"),
            MaskStyle::Full.apply("a much longer secret value"),
        );
    }

    /// A value too short for its style is masked entirely rather than shown.
    ///
    /// The failure this refuses is a mask that stops masking on the values it
    /// was misapplied to: `last4` over a four-character card number is the
    /// whole number, printed by code that believes it is redacting.
    #[test]
    fn a_value_too_short_for_its_style_is_masked_whole() {
        assert_eq!(MaskStyle::Last4.apply("4242"), "••••••••");
        assert_eq!(MaskStyle::Last2.apply("7"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("not-an-address"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("@example.com"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("alice@"), "••••••••");
    }

    /// Masking counts characters, not bytes: a multi-byte value must not panic
    /// on a slice boundary, and must keep the count the style promises.
    #[test]
    fn masking_counts_characters_not_bytes() {
        assert_eq!(MaskStyle::Last2.apply("naïve café"), "••••••••fé");
    }
}
