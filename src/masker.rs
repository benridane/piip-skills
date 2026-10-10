//! Masking functions, rule application and
//! detection with positions.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Serialize;

use crate::config::Settings;
use crate::detector::{self, digits};
use crate::patterns::{self, Action, MaskFn, Provider, RULES, Rule, Tracked};
use crate::regex::Re;

/// One detected PII item. Offsets are character (code point) indices into
/// the original text; `value` is the normalized (half-width) value.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub source: &'static str,
    pub rule: String,
    #[serde(rename = "type")]
    pub ptype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub start: usize,
    pub end: usize,
    pub score: f64,
    pub value: String,
    pub masked: String,
}

pub struct Masker<'a> {
    pub settings: &'a Settings,
}

impl<'a> Masker<'a> {
    pub fn new(settings: &'a Settings) -> Self {
        Masker { settings }
    }

    /// Mask PII in free text, full-width aware.
    ///
    /// Rules run on normalized text; characters that masking left alone are
    /// then taken from the original. Custom patterns run last, on the
    /// original characters.
    pub fn mask_text(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }

        let normalized = patterns::normalize(text);
        let mut tracked = Tracked::new(&normalized, normalized != text);
        self.apply_text_rules(&mut tracked);
        let restored = tracked.restore(text);

        self.mask_custom_patterns(&restored)
    }

    fn apply_text_rules(&self, tracked: &mut Tracked) {
        for rule in RULES.iter() {
            if !self.settings.should_mask_type(rule.ptype) {
                continue;
            }
            // On a PCRE2 error (match limit etc.) the rule is skipped and
            // the text is kept.
            let Some(matches) = rule.re.captures_all(&tracked.text) else {
                continue;
            };
            let edits: Vec<(usize, usize, String)> = matches
                .iter()
                .filter_map(|groups| {
                    let (start, end) = groups.get(rule.group).copied().flatten()?;
                    let value = &tracked.text[start..end];
                    let masked = mask_rule_value(rule, value)?;
                    (masked != value).then_some((start, end, masked))
                })
                .collect();
            tracked.apply(&edits);
        }
    }

    fn mask_custom_patterns(&self, text: &str) -> String {
        if !self.settings.should_mask_type("custom") {
            return text.to_string();
        }
        let mut text = text.to_string();
        for custom in &self.settings.custom_patterns {
            if let Some(replaced) = custom
                .re
                .replace_all(&text, |_, _| custom.replacement.clone())
            {
                text = replaced;
            }
        }
        text
    }

    /// Find PII with positions, using the same rules as `mask_text`.
    ///
    /// Rules see the same normalized text independently; a finding that
    /// overlaps one from an earlier rule is dropped, mirroring how earlier
    /// rules consume text during masking.
    pub fn find_all(&self, text: &str) -> Vec<Finding> {
        let normalized = patterns::normalize(text);
        let byte_to_char = char_index_map(&normalized);
        // Claimed value spans, start -> end (non-overlapping by construction).
        let mut claimed: BTreeMap<usize, usize> = BTreeMap::new();
        let mut found = Vec::new();

        for rule in RULES.iter() {
            if !self.settings.should_mask_type(rule.ptype) {
                continue;
            }
            let Some(matches) = rule.re.captures_all(&normalized) else {
                continue;
            };
            for groups in matches {
                let Some((start, end)) = groups.get(rule.group).copied().flatten() else {
                    continue;
                };
                if start == end {
                    continue;
                }
                let value = &normalized[start..end];
                if let Some(v) = rule.validate
                    && !detector::validate(v, value)
                {
                    continue;
                }
                let before = claimed.range(..end).next_back();
                if before.is_some_and(|(_, &e)| e > start) {
                    continue;
                }
                claimed.insert(start, end);

                found.push(Finding {
                    source: "builtin",
                    rule: rule.id.clone(),
                    ptype: rule.ptype.to_string(),
                    provider: provider_for(rule, value),
                    start: byte_to_char[start],
                    end: byte_to_char[end],
                    score: detector::confidence(rule.ptype),
                    value: value.to_string(),
                    masked: masked_value(rule, value),
                });
            }
        }

        if self.settings.should_mask_type("custom") {
            let original_map = char_index_map(text);
            for custom in &self.settings.custom_patterns {
                for groups in custom.re.captures_all(text).unwrap_or_default() {
                    let (start, end) = groups[0].expect("group 0");
                    if start == end {
                        continue;
                    }
                    found.push(Finding {
                        source: "custom",
                        rule: "custom".into(),
                        ptype: "custom".into(),
                        provider: Some(custom.label.clone()),
                        start: original_map[start],
                        end: original_map[end],
                        score: 1.0,
                        value: text[start..end].to_string(),
                        masked: custom.replacement.clone(),
                    });
                }
            }
        }

        found.sort_by_key(|f| (f.start, f.end));
        found
    }

    /// Field-aware masking of a single value (form fields, JSON keys).
    pub fn mask_value(&self, field: &str, value: &str) -> String {
        if value.is_empty() || is_already_masked(value) {
            return value.to_string();
        }
        let Some(ptype) = detector::detect_pii_type(field, value) else {
            return value.to_string();
        };
        if !self.settings.should_mask_type(ptype) || self.settings.has_consent_phrase(value) {
            return value.to_string();
        }
        apply_masking_by_type(ptype, value)
    }
}

/// Map each byte offset (at char boundaries, plus len) to a char index.
pub fn char_index_map(s: &str) -> Vec<usize> {
    let mut map = vec![0; s.len() + 1];
    let mut idx = 0;
    for (b, c) in s.char_indices() {
        for k in 0..c.len_utf8() {
            map[b + k] = idx;
        }
        idx += 1;
    }
    map[s.len()] = idx;
    map
}

fn provider_for(rule: &Rule, value: &str) -> Option<String> {
    match rule.provider {
        Provider::None => None,
        Provider::Static(p) => Some(p.to_string()),
        Provider::Hosting => detector::get_hosting_provider(value).map(str::to_string),
        Provider::Ai => detector::get_ai_provider(value).map(str::to_string),
    }
}

fn masked_value(rule: &Rule, value: &str) -> String {
    match rule.action {
        Action::Replace(s) => s.to_string(),
        Action::Mask(f) => apply_mask_fn(f, value),
    }
}

/// The replacement for a rule's value group, or None when the value is
/// empty or fails validation (the match is then left as it is).
fn mask_rule_value(rule: &Rule, value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Some(v) = rule.validate
        && !detector::validate(v, value)
    {
        return None;
    }
    Some(masked_value(rule, value))
}

fn is_already_masked(value: &str) -> bool {
    value.contains("***") || value == "[REDACTED]"
}

pub fn apply_masking_by_type(ptype: &str, value: &str) -> String {
    match ptype {
        "email" => mask_email(value),
        "phone" => mask_phone(value),
        "name" => mask_name(value),
        "address" => mask_address(value),
        "card" => mask_credit_card(value),
        "ssn" => mask_ssn(value),
        "password" => "[REDACTED]".into(),
        "token" => mask_token(value),
        "hosting" => mask_hosting_id(value),
        "ip" => mask_ip(value),
        _ => value.to_string(),
    }
}

pub fn apply_mask_fn(f: MaskFn, value: &str) -> String {
    match f {
        MaskFn::KeepPrefix => first_chars(value, 4) + "***",
        MaskFn::Token => mask_token(value),
        MaskFn::UrlSecret => mask_url_secret(value),
        MaskFn::Dob => mask_dob(value),
        MaskFn::Bank => mask_bank(value),
        MaskFn::IdDoc => "*".repeat(value.chars().count().max(4)),
        MaskFn::PersonName => mask_person_name(value),
        MaskFn::LabeledAddress => mask_labeled_address(value),
        MaskFn::Phone => mask_phone(value),
        MaskFn::AccountId => first_chars(value, 1) + "***",
        MaskFn::Email => mask_email(value),
        MaskFn::CreditCard => mask_credit_card(value),
        MaskFn::Ssn => mask_ssn(value),
        MaskFn::Mynumber => mask_mynumber(value),
        MaskFn::Ip => mask_ip(value),
        MaskFn::HostingId => mask_hosting_id(value),
        MaskFn::Name => mask_name(value),
    }
}

fn first_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn last_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    s.chars().skip(count.saturating_sub(n)).collect()
}

/// taro.yamada@example.jp → t***@example.jp
pub fn mask_email(email: &str) -> String {
    if !detector::is_email(email) {
        return email.to_string();
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return "***@***".into();
    }
    format!("{}***@{}", first_chars(parts[0], 1), parts[1])
}

/// 090-1234-5678 → ***-***-5678
pub fn mask_phone(phone: &str) -> String {
    let d = digits(phone);
    if d.len() < 7 {
        return phone.to_string();
    }
    format!("***-***-{}", &d[d.len() - 4..])
}

/// Keep the first character of each whitespace-separated part.
pub fn mask_name(name: &str) -> String {
    name.split_ascii_whitespace()
        .map(|part| first_chars(part, 1) + &"*".repeat(part.chars().count() - 1))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Field-based address masking: keep the first part.
pub fn mask_address(address: &str) -> String {
    let parts: Vec<&str> = address
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|p| !p.is_empty())
        .collect();
    match parts.len() {
        0 => "***".into(),
        1 => {
            let len = address.chars().count();
            if len > 4 {
                first_chars(address, 2) + &"*".repeat(3.min(len - 2))
            } else {
                "***".into()
            }
        }
        2 => format!("{} ***", parts[0]),
        _ => format!("{} *** ***", parts[0]),
    }
}

/// 4532-1234-5678-9014 → ****-****-****-9014
pub fn mask_credit_card(card: &str) -> String {
    let d = digits(card);
    if !(13..=19).contains(&d.len()) {
        return card.to_string();
    }
    format!("****-****-****-{}", &d[d.len() - 4..])
}

pub fn mask_ssn(ssn: &str) -> String {
    let d = digits(ssn);
    if d.len() != 9 {
        return "***-**-****".into();
    }
    format!("***-**-{}", &d[5..])
}

pub fn mask_mynumber(value: &str) -> String {
    let d = digits(value);
    if d.len() != 12 {
        return "****-****-****".into();
    }
    format!("****-****-{}", &d[8..])
}

/// First and last 4 for long tokens, first 4 for medium ones.
pub fn mask_token(token: &str) -> String {
    let len = token.chars().count();
    if len >= 32 {
        first_chars(token, 4) + &"*".repeat(len - 8) + &last_chars(token, 4)
    } else if len >= 12 {
        first_chars(token, 4) + "***"
    } else {
        "***".into()
    }
}

static URL_SECRET_HEAD: LazyLock<Re> =
    LazyLock::new(|| Re::delimited(r"#^[a-z][a-z0-9+.-]*://[^/]+/#i").unwrap());

pub fn mask_url_secret(url: &str) -> String {
    match URL_SECRET_HEAD.find(url) {
        Some((s, e)) => format!("{}***", &url[s..e]),
        None => "***".into(),
    }
}

pub fn mask_dob(date: &str) -> String {
    if date.contains('年') {
        "****年**月**日".into()
    } else {
        "****-**-**".into()
    }
}

pub fn mask_bank(account: &str) -> String {
    format!("***{}", last_chars(account, 4))
}

/// Labeled person name: keep the first character of each part; one-char
/// parts are masked too, honorifics (様, さん, 殿, 御中) are kept.
pub fn mask_person_name(name: &str) -> String {
    let mut out = String::new();
    let mut part = String::new();
    let flush = |part: &mut String, out: &mut String| {
        if part.is_empty() {
            return;
        }
        if matches!(part.as_str(), "様" | "さん" | "殿" | "御中") || part.trim().is_empty() {
            out.push_str(part);
        } else {
            let len = part.chars().count();
            if len == 1 {
                out.push('*');
            } else {
                out.push_str(&(first_chars(part, 1) + &"*".repeat(len - 1)));
            }
        }
        part.clear();
    };
    for c in name.chars() {
        if c == ' ' {
            flush(&mut part, &mut out);
            out.push(' ');
        } else {
            part.push(c);
        }
    }
    flush(&mut part, &mut out);
    out
}

static ADDRESS_LEAD: LazyLock<Re> = LazyLock::new(|| {
    Re::delimited(&format!(
        "/^(?:{}|{}|{})/u",
        patterns::PREFECTURES,
        patterns::DESIGNATED_CITIES,
        patterns::TOKYO_WARDS
    ))
    .unwrap()
});

/// Keep only a leading prefecture or city.
pub fn mask_labeled_address(address: &str) -> String {
    match ADDRESS_LEAD.find(address) {
        Some((s, e)) => format!("{}***", &address[s..e]),
        None => "***".into(),
    }
}

/// 192.168.1.10 → 192.***.***.10, 2001:db8::1:2:3 → 2001:db8:***
pub fn mask_ip(ip: &str) -> String {
    if let Some(v6) = detector::parse_ipv6(ip) {
        let s = v6.segments();
        return format!("{:x}:{:x}:***", s[0], s[1]);
    }
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.***.***.{}", parts[0], parts[3])
    } else {
        "***.***.***.***".into()
    }
}

static HOSTING_MASKS: LazyLock<Vec<Re>> = LazyLock::new(|| {
    [
        r"/^xs\d{5,8}$/i",
        r"/^sv\d{3,5}$/i",
        r"/^[a-z]{3}\d{5}$/i",
        r"/^gnc[a-z0-9]{8,12}$/i",
        r"/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i",
        r"/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/",
    ]
    .iter()
    .map(|p| Re::delimited(p).unwrap())
    .collect()
});

pub fn mask_hosting_id(value: &str) -> String {
    let len = value.chars().count();
    let lower = value.to_ascii_lowercase();
    let h = &*HOSTING_MASKS;

    if h[0].is_match(value) {
        return first_chars(value, 2) + "***" + &last_chars(value, 3);
    }
    if h[1].is_match(value) {
        return first_chars(value, 2) + "***" + &last_chars(value, 1);
    }
    if h[2].is_match(value) {
        return first_chars(value, 3) + "***" + &last_chars(value, 2);
    }
    for domain in [".sakura.ne.jp", ".lolipop.jp", ".mixh.jp"] {
        if lower.ends_with(domain) {
            return format!("***{domain}");
        }
    }
    if h[3].is_match(value) {
        return "gnc***".to_string() + &last_chars(value, 4);
    }
    if value.len() == 12 && value.bytes().all(|b| b.is_ascii_digit()) {
        return "****-****-".to_string() + &value[8..];
    }
    if h[4].is_match(value) {
        return format!(
            "****-****-****-****-{}",
            value.rsplit('-').next().unwrap_or("")
        );
    }
    if h[5].is_match(value) {
        return if len > 10 {
            first_chars(value, 3) + "***" + &last_chars(value, 3)
        } else {
            first_chars(value, 2) + "***" + &last_chars(value, 2)
        };
    }
    if len > 6 {
        return first_chars(value, 2) + "***" + &last_chars(value, 2);
    }
    "***".into()
}
