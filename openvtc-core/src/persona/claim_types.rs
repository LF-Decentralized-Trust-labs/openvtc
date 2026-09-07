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
//! the copy is the private `TABLE` in this file plus [`UNREGISTERED`].
//!
//! # This is not a security control, and it must not be described as one
//!
//! Masking here happens *after* the value has been fetched, decrypted by the
//! agent, sent over DIDComm and parked in this process's memory. Everything
//! that could read it before still can. What it defends against is a person
//! reading the terminal over a shoulder, and a screenshot or a screen share
//! carrying a card number to an audience that was never asked.
//!
//! # Masking is the half of the registry this client can honour
//!
//! The registry's §3.3 makes `mask` and `sensitivity` two decisions, not one,
//! and they land in two different places:
//!
//! - **`mask`** is a rendering. Any type whose style is not `none` is shown
//!   reduced, whatever its sensitivity — which is why `email.work` is masked
//!   here despite being `normal`. An address is worth hiding from the person
//!   behind you without being worth withholding from every listing.
//! - **`sensitivity: high`** means the value is *withheld from a listing that
//!   did not explicitly ask for sensitive values*. That is the half that is not
//!   cosmetic, it is a read-path control, and **it does not exist**:
//!   `persona_attribute_list` takes `include_values` and nothing finer, so a
//!   listing this pane asks for values in is sent every card number the holder
//!   holds. [`Sensitivity`] is carried here so a caller can read it, and
//!   nothing in this crate can act on it.
//!
//! So the mask is what makes a missing control visible, not a substitute for
//! it. A `high` type is masked *because its style says so*, not because
//! anything here withheld it.

/// How carefully a value is shown **to its own holder**.
///
/// Not linkability, and not what it takes to release the value — the registry's
/// §3 keeps those three apart because a mechanism that reads one as a proxy for
/// another hides the wrong things and warns about the wrong things. A payment
/// card is highly sensitive and barely linkable; a nickname can be the reverse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sensitivity {
    /// Nothing beyond whatever [`MaskStyle`] the type carries.
    #[default]
    Normal,
    /// Additionally withheld from a listing that did not ask for sensitive
    /// values — a read-path control this client cannot exercise. See the module
    /// header.
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
    ///
    /// The style alone decides, per §3.3 — a `high` type reaches this through
    /// its style like any other. Reading `sensitivity` as the trigger is the
    /// tangle the registry's first draft had and its second draft names: it
    /// left `email.*` carrying an `emailLocal` style that no rule could ever
    /// apply, while §1 used `a•••@example.com` to motivate the registry.
    #[must_use]
    pub fn masks_by_default(self) -> bool {
        self.mask.hides_anything()
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

/// The floor: what a token resolves to when nothing more specific supplies an
/// axis.
///
/// The conservative answer, and the registry's §4 rule 4: a vocabulary nobody
/// has reasoned about is exactly the one nothing is known about, and an unknown
/// value rendered in the clear is a decision nobody made. `x:` tokens are
/// unregistered by construction and land here too.
pub const UNREGISTERED: ClaimTypeDefaults = ClaimTypeDefaults {
    sensitivity: Sensitivity::High,
    mask: MaskStyle::Full,
};

/// The vendored table, in `claim-types.json`'s order so the two diff against
/// each other by eye.
const TABLE: &[(&str, Sensitivity, MaskStyle)] = &[
    // Family entries, matched as prefixes. Without them `payment.somethingNew`
    // resolves to the floor, and a gated family becomes leavable by inventing a
    // token. `name` is also an exact token: a pool that keeps one
    // undifferentiated name is using it.
    ("payment", Sensitivity::High, MaskStyle::Full),
    ("gov", Sensitivity::High, MaskStyle::Full),
    ("name", Sensitivity::Normal, MaskStyle::None),
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

/// The namespace the registry leaves open, and never resolves through a family.
const EXTENSION_PREFIX: &str = "x:";

impl Sensitivity {
    /// Position in `claim-types.json`'s `strictness` ordering, most protective
    /// first.
    fn strictness(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Normal => 1,
        }
    }
}

impl MaskStyle {
    /// Position in `claim-types.json`'s `strictness` ordering, most protective
    /// first. `last2` outranks `last4` because it shows fewer characters.
    fn strictness(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Last2 => 1,
            Self::Last4 => 2,
            Self::EmailLocal => 3,
            Self::None => 4,
        }
    }
}

impl ClaimTypeDefaults {
    /// The more protective of two answers, taken per axis.
    ///
    /// Per axis rather than whole-record, because the axes are independent
    /// (§3) and a record chosen as a unit would carry one axis's answer on the
    /// strength of another's.
    fn tightest(self, other: Self) -> Self {
        Self {
            sensitivity: if self.sensitivity.strictness() <= other.sensitivity.strictness() {
                self.sensitivity
            } else {
                other.sensitivity
            },
            mask: if self.mask.strictness() <= other.mask.strictness() {
                self.mask
            } else {
                other.mask
            },
        }
    }
}

/// Resolve a claim type to how its value is shown — the registry's §4, minus
/// the rule this client cannot reach.
///
/// 1. Rule 1 — a holder's explicit override — is **not implemented, because
///    there is nowhere to store one.** `persona/attribute/put` has no
///    `sensitivity` or `mask` member and the SDK's attribute carries neither,
///    so the choice the rule resolves first cannot currently be made. When it
///    can, it belongs above everything here.
/// 2. An exact entry is used **as written**, and is not compared against
///    anything: it is a decision someone made about that token.
/// 3. Otherwise the longest registered *prefix* is taken together with
///    [`UNREGISTERED`], and the more protective of the two wins on each axis.
///    A family entry can therefore only ever tighten — `name` as a prefix does
///    not make an unregistered `name.somethingNew` visible.
/// 4. Otherwise the floor.
///
/// Rule 3 is what stops a gated family being left by inventing a token:
/// without it `payment.giftCard` would resolve to the floor, whose `release`
/// is `consent` — weaker than every registered member of the family it plainly
/// belongs to.
#[must_use]
pub fn resolve(claim_type: &str) -> ClaimTypeDefaults {
    if let Some(exact) = entry(claim_type) {
        return exact;
    }
    // The open namespace is unregistered by construction, so it never inherits
    // a family's answer: `x:payment.card` is a token this registry has never
    // seen that happens to read like one it has.
    if claim_type.starts_with(EXTENSION_PREFIX) {
        return UNREGISTERED;
    }
    longest_registered_prefix(claim_type)
        .map_or(UNREGISTERED, |family| family.tightest(UNREGISTERED))
}

fn entry(claim_type: &str) -> Option<ClaimTypeDefaults> {
    TABLE
        .iter()
        .find(|(token, _, _)| *token == claim_type)
        .map(|(_, sensitivity, mask)| ClaimTypeDefaults {
            sensitivity: *sensitivity,
            mask: *mask,
        })
}

/// The longest registered ancestor of a token, on `.` boundaries.
///
/// Boundaries matter: `paymentx.foo` is not in the `payment` family, and a
/// plain `starts_with` would put it there.
fn longest_registered_prefix(claim_type: &str) -> Option<ClaimTypeDefaults> {
    let mut cut = claim_type.len();
    while let Some(dot) = claim_type[..cut].rfind('.') {
        if let Some(found) = entry(&claim_type[..dot]) {
            return Some(found);
        }
        cut = dot;
    }
    None
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
        assert_eq!(resolve("phone.mobile").mask, MaskStyle::Last2);
        assert!(resolve("gov.id.passport").masks_by_default());
        assert!(!resolve("org.role").masks_by_default());
        // An exact entry is used as written and is not compared against its
        // family: `payment.card` shows its last four even though the `payment`
        // family entry is `full`. Someone decided that about that token.
        assert_eq!(resolve("payment.card").mask, MaskStyle::Last4);
    }

    /// An unregistered token with no registered family gets the conservative
    /// answer.
    ///
    /// This is the case the floor exists for: a build that has never heard of a
    /// vocabulary knows nothing about what it holds, and showing it in the
    /// clear would be a decision nobody made.
    #[test]
    fn an_unknown_type_masks_fully() {
        for token in ["medical.condition", "", "somethingElse"] {
            let resolved = resolve(token);
            assert_eq!(resolved.sensitivity, Sensitivity::High, "{token}");
            assert_eq!(resolved.mask, MaskStyle::Full, "{token}");
        }
    }

    /// A new token in a gated family inherits the family, not the floor.
    ///
    /// Without this a gated family is leavable by inventing a token:
    /// `payment.giftCard` would resolve to the unregistered default, whose
    /// `release` is weaker than every registered member of the family it
    /// plainly belongs to.
    #[test]
    fn a_new_token_inherits_its_registered_family() {
        assert_eq!(resolve("payment.giftCard"), resolve("payment"));
        assert_eq!(resolve("gov.id.somethingNew").mask, MaskStyle::Full);
    }

    /// A family can only tighten. `name` is `normal`/`none`, and an unknown
    /// `name.*` still lands on the floor rather than being shown in the clear
    /// on the strength of its prefix.
    #[test]
    fn a_family_never_loosens_the_floor() {
        assert_eq!(resolve("name.somethingNew"), UNREGISTERED);
        // …while the family token itself, being an exact entry, is used as
        // written.
        assert_eq!(resolve("name").mask, MaskStyle::None);
    }

    /// A prefix is a prefix on `.` boundaries. `paymentx` is not in the
    /// `payment` family, and a plain `starts_with` would put it there.
    #[test]
    fn a_family_matches_on_segment_boundaries() {
        assert_eq!(resolve("paymentx.token"), UNREGISTERED);
        assert_eq!(resolve("governance.role"), UNREGISTERED);
    }

    /// The open namespace never inherits a family: `x:payment.card` is a token
    /// this registry has never seen that happens to read like one it has.
    #[test]
    fn an_extension_token_never_inherits() {
        assert_eq!(resolve("x:employer.badge"), UNREGISTERED);
        assert_eq!(resolve("x:payment.card"), UNREGISTERED);
        assert_eq!(resolve("x:name.given"), UNREGISTERED);
    }

    /// The style masks whatever the sensitivity says. `email.work` is `normal`
    /// and masked, which is §3.3's whole point: an address is worth hiding from
    /// the person behind you without being worth withholding from a listing.
    #[test]
    fn a_normal_type_is_masked_by_its_style() {
        let email = resolve("email.work");
        assert_eq!(email.sensitivity, Sensitivity::Normal);
        assert!(email.masks_by_default());
        assert_eq!(email.render("alice@example.com"), "a•••@example.com");
    }

    /// …and a `normal` type with no style is shown as it is held. Masking
    /// everything would teach the reveal as a reflex, and a reveal pressed by
    /// reflex protects nothing.
    #[test]
    fn a_type_with_no_style_is_shown_whole() {
        let name = resolve("name.given");
        assert!(!name.masks_by_default());
        assert_eq!(name.render("Alice"), "Alice");
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
