//! Validators, provider lookup and field-name
//! based detection for structured data (form fields, JSON keys).

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use crate::patterns::{self, Validate};
use crate::regex::Re;

fn re(src: &str) -> Re {
    Re::delimited(src).unwrap_or_else(|e| panic!("{e}"))
}

fn res(list: &[(&'static str, &str)]) -> Vec<(&'static str, Re)> {
    list.iter().map(|(name, src)| (*name, re(src))).collect()
}

/// Field name patterns for PII detection (multilingual), in priority order.
const FIELD_PATTERNS: &[(&str, &[&str])] = &[
    (
        "email",
        &[
            "email",
            "e-mail",
            "mail",
            "メール",
            "メールアドレス",
            "eメール",
        ],
    ),
    (
        "phone",
        &[
            "phone",
            "tel",
            "telephone",
            "mobile",
            "cell",
            "fax",
            "contact",
            "電話",
            "電話番号",
            "TEL",
            "携帯",
            "連絡先",
            "FAX",
        ],
    ),
    (
        "name",
        &[
            "name",
            "first",
            "last",
            "fname",
            "lname",
            "fullname",
            "full_name",
            "given",
            "family",
            "surname",
            "nickname",
            "氏名",
            "名前",
            "お名前",
            "姓",
            "名",
            "フリガナ",
            "ふりがな",
        ],
    ),
    (
        "address",
        &[
            "address",
            "street",
            "city",
            "zip",
            "postal",
            "prefecture",
            "state",
            "country",
            "region",
            "location",
            "addr",
            "住所",
            "都道府県",
            "市区町村",
            "番地",
            "郵便番号",
            "〒",
        ],
    ),
    (
        "card",
        &[
            "card",
            "credit",
            "ccn",
            "payment",
            "cardnumber",
            "card_number",
            "カード",
            "クレジット",
            "カード番号",
        ],
    ),
    (
        "ssn",
        &[
            "ssn",
            "social",
            "security",
            "mynumber",
            "national_id",
            "tax_id",
            "マイナンバー",
            "個人番号",
        ],
    ),
    (
        "password",
        &[
            "password",
            "pwd",
            "pass",
            "secret",
            "passwd",
            "パスワード",
            "暗証番号",
        ],
    ),
    (
        "token",
        &[
            "token",
            "api",
            "key",
            "secret",
            "apikey",
            "api_key",
            "access_token",
            "openai",
            "claude",
            "anthropic",
            "gemini",
            "cohere",
            "huggingface",
            "replicate",
            "ai_key",
            "ai_token",
            "トークン",
            "APIキー",
            "AIキー",
        ],
    ),
    (
        "dob",
        &[
            "dob",
            "birth",
            "birthday",
            "birthdate",
            "date_of_birth",
            "生年月日",
            "誕生日",
        ],
    ),
    (
        "ip",
        &["ip", "ip_address", "ipaddress", "remote_addr", "IPアドレス"],
    ),
    (
        "url",
        &[
            "url",
            "website",
            "homepage",
            "site",
            "link",
            "URL",
            "ホームページ",
            "サイト",
        ],
    ),
    (
        "hosting",
        &[
            "server",
            "server_id",
            "account_id",
            "hosting",
            "subscription",
            "project_id",
            "xserver",
            "sakura",
            "aws",
            "azure",
            "gcp",
            "サーバー",
            "サーバーID",
            "アカウントID",
        ],
    ),
];

static EMAIL: LazyLock<Re> =
    LazyLock::new(|| re(r"/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/"));
static URL: LazyLock<Re> = LazyLock::new(|| re(r#"/\bhttps?:\/\/[^\s<>"']+/i"#));
static URL_FULL: LazyLock<Re> =
    LazyLock::new(|| re(r"/^[a-z][a-z0-9+.\-]*:\/\/[^\s\/?#]+[^\s]*$/i"));
static SSN: LazyLock<Re> = LazyLock::new(|| re(r"/\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/"));
static MYNUMBER: LazyLock<Re> = LazyLock::new(|| re(r"/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/"));
static IPV4: LazyLock<Re> = LazyLock::new(|| {
    re(
        r"/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/",
    )
});

static PHONE_PATTERNS: LazyLock<Vec<(&'static str, Re)>> = LazyLock::new(|| {
    res(&[
        ("jp_mobile", r"/\b0[789]0[-\s]?\d{4}[-\s]?\d{4}\b/"),
        ("jp_landline", r"/\b0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}\b/"),
        ("jp_tollfree", r"/\b0[18]20[-\s]?\d{3}[-\s]?\d{3,4}\b/"),
        (
            "international",
            r"/\+\d{1,3}[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{2,4}/",
        ),
        ("us_standard", r"/\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/"),
        ("generic", r"/\b\d{2,4}[-.\s]\d{2,4}[-.\s]\d{2,4}\b/"),
    ])
});

static HOSTING_PATTERNS: LazyLock<Vec<(&'static str, Re)>> = LazyLock::new(|| {
    res(&[
        ("xserver_account", r"/\bxs\d{5,8}\b/i"),
        ("xserver_server", r"/\bsv\d{3,5}\b/i"),
        ("sakura_account", r"/\b[a-z]{3}\d{5}\b/i"),
        ("sakura_domain", r"/\b[\w-]+\.sakura\.ne\.jp\b/i"),
        ("aws_account", r"/\b\d{12}\b/"),
        (
            "azure_guid",
            r"/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i",
        ),
        ("gcp_project", r"/\b[a-z][a-z0-9-]{4,28}[a-z0-9]\b/"),
        ("conoha_account", r"/\bgnc[a-z0-9]{8,12}\b/i"),
        ("lolipop_domain", r"/\b[\w-]+\.lolipop\.jp\b/i"),
        ("mixhost_domain", r"/\b[\w-]+\.mixh\.jp\b/i"),
    ])
});

static AI_KEY_PATTERNS: LazyLock<Vec<(&'static str, Re)>> = LazyLock::new(|| {
    res(&[
        ("openai_legacy", r"/\bsk-[A-Za-z0-9]{20,100}\b/"),
        ("openai_project", r"/\bsk-proj-[A-Za-z0-9]{20,100}\b/"),
        ("anthropic", r"/\bsk-ant-[A-Za-z0-9_-]{30,}\b/"),
        ("google_ai", r"/\bAIza[A-Za-z0-9_-]{30,40}\b/"),
        ("cohere", r"/\b[A-Za-z0-9]{30,50}-co\b/"),
        ("huggingface", r"/\bhf_[A-Za-z0-9]{20,40}\b/"),
        ("replicate", r"/\br8_[A-Za-z0-9]{20,50}\b/"),
        ("azure_openai", r"/\b[a-f0-9]{32}\b/"),
        (
            "generic_ai_key",
            r"/\b(?:sk-|ai-|api-)[A-Za-z0-9_-]{20,100}\b/",
        ),
    ])
});

static NAME_EXCLUSION: LazyLock<Re> = LazyLock::new(|| re(patterns::NAME_EXCLUSION_PATTERN));
static NAME_PLACEHOLDER: LazyLock<Re> = LazyLock::new(|| {
    re(
        r"/^(?:未定|なし|無し|不明|匿名|非公開|未記入|省略|同上|テスト|test|none|n\/a|anonymous|unknown|same)$/iu",
    )
});
static ACCOUNT_PLACEHOLDER: LazyLock<Re> = LazyLock::new(|| {
    re(r"/^(?:未定|なし|無し|不明|未登録|忘れました|わかりません|none|n\/a|unknown|\*+|x+)$/iu")
});
static SECRET_PLACEHOLDER: LazyLock<Re> = LazyLock::new(|| {
    re(r"/^(?:\$|%|\{|getenv|env\(|process\.env|null$|true$|false$|\*+$|x{3,}$|\[REDACTED\]$)/i")
});
static PHONE_EXTENSION: LazyLock<Re> =
    LazyLock::new(|| re(r"/[\t ]*[(]?(?:内線|ext\.?|x)[\t ]*[0-9]{1,6}[)]?$/iu"));
static TOKEN_CHARS: LazyLock<Re> = LazyLock::new(|| re(r"/[0-9\-_+\/=.]/"));
static AI_PREFIX: LazyLock<Re> = LazyLock::new(|| re(r"/^(sk-|ai-|api-)/i"));

pub fn digits(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Run a rule validator.
pub fn validate(v: Validate, value: &str) -> bool {
    match v {
        Validate::IsSecretValue => !SECRET_PLACEHOLDER.is_match(value),
        Validate::HasTokenChars => TOKEN_CHARS.is_match(value),
        Validate::IsPersonName => is_person_name(value),
        Validate::HasDigit => value.chars().any(|c| c.is_ascii_digit()),
        Validate::IsPhoneValue => {
            let main = PHONE_EXTENSION
                .replace_all(value, |_, _| String::new())
                .unwrap_or_else(|| value.to_string());
            let n = digits(&main).len();
            (9..=15).contains(&n)
        }
        Validate::IsAccountValue => !ACCOUNT_PLACEHOLDER.is_match(value),
        Validate::IsCardNumber => {
            let d = digits(value);
            (13..=19).contains(&d.len()) && is_luhn_valid(&d)
        }
        Validate::IsSsnNumber => {
            let d = digits(value);
            d.len() == 9
                && !d.starts_with("000")
                && !d.starts_with("666")
                && !d.starts_with('9')
                && &d[3..5] != "00"
                && &d[5..9] != "0000"
        }
        Validate::IsMynumberNumber => is_mynumber_checkdigit(&digits(value)),
        Validate::IsMaskableIpv6 => is_maskable_ipv6(value),
        Validate::IsAiKey => is_ai_key(value),
    }
}

pub fn is_person_name(value: &str) -> bool {
    !NAME_EXCLUSION.is_match(value) && !NAME_PLACEHOLDER.is_match(value.trim())
}

pub fn is_luhn_valid(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let parity = digits.len() % 2;
    let sum: u32 = digits
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            let mut d = (b - b'0') as u32;
            if i % 2 == parity {
                d *= 2;
            }
            if d > 9 {
                d -= 9;
            }
            d
        })
        .sum();
    sum.is_multiple_of(10)
}

pub fn is_mynumber_checkdigit(d: &str) -> bool {
    if d.len() != 12 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let b = d.as_bytes();
    let sum: u32 = (0..11).map(|i| (b[i] - b'0') as u32 * weights[i]).sum();
    let rem = sum % 11;
    let check = if rem <= 1 { 0 } else { 11 - rem };
    (b[11] - b'0') as u32 == check
}

pub fn parse_ipv6(value: &str) -> Option<Ipv6Addr> {
    value.parse::<Ipv6Addr>().ok()
}

/// Valid IPv6 with at least three non-empty groups (skips "::1", "a::b").
pub fn is_maskable_ipv6(value: &str) -> bool {
    parse_ipv6(value).is_some() && value.split(':').filter(|g| !g.is_empty()).count() >= 3
}

fn unique_chars(value: &str) -> usize {
    let mut chars: Vec<char> = value.chars().collect();
    chars.sort_unstable();
    chars.dedup();
    chars.len()
}

pub fn is_ai_key(value: &str) -> bool {
    ai_provider_key(value).is_some()
}

fn ai_provider_key(value: &str) -> Option<&'static str> {
    for (name, pattern) in AI_KEY_PATTERNS.iter() {
        if !pattern.is_match(value) {
            continue;
        }
        match *name {
            "azure_openai" => {
                if value.len() == 32
                    && value.bytes().all(|b| b.is_ascii_hexdigit())
                    && unique_chars(&value.to_lowercase()) >= 8
                {
                    return Some(name);
                }
            }
            "generic_ai_key" => {
                let len = value.len();
                if (20..=100).contains(&len) && AI_PREFIX.is_match(value) {
                    return Some(name);
                }
            }
            _ => return Some(name),
        }
    }
    None
}

pub fn get_ai_provider(value: &str) -> Option<&'static str> {
    // Provider lookup skips the generic length check.
    for (name, pattern) in AI_KEY_PATTERNS.iter() {
        if !pattern.is_match(value) {
            continue;
        }
        match *name {
            "azure_openai" => {
                if value.len() == 32
                    && value.bytes().all(|b| b.is_ascii_hexdigit())
                    && unique_chars(&value.to_lowercase()) >= 8
                {
                    return Some("Azure OpenAI");
                }
            }
            "generic_ai_key" => {
                if AI_PREFIX.is_match(value) {
                    return Some("AI Service");
                }
            }
            other => {
                return Some(match other {
                    "openai_legacy" | "openai_project" => "OpenAI",
                    "anthropic" => "Anthropic",
                    "google_ai" => "Google AI",
                    "cohere" => "Cohere",
                    "huggingface" => "Hugging Face",
                    "replicate" => "Replicate",
                    _ => "Unknown AI Service",
                });
            }
        }
    }
    None
}

pub fn get_hosting_provider(value: &str) -> Option<&'static str> {
    for (name, pattern) in HOSTING_PATTERNS.iter() {
        if pattern.is_match(value) {
            return Some(match *name {
                "xserver_account" | "xserver_server" => "Xserver",
                "sakura_account" | "sakura_domain" => "Sakura",
                "aws_account" => "AWS",
                "azure_guid" => "Azure",
                "gcp_project" => "GCP",
                "conoha_account" => "ConoHa",
                "lolipop_domain" => "Lolipop",
                "mixhost_domain" => "mixhost",
                _ => "Unknown",
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Field-based detection (structured data).

/// Field names that are never masked (CMS and form framework conventions).
pub fn is_system_field(field: &str) -> bool {
    const SYSTEM: &[&str] = &[
        "_wpnonce",
        "_wp_http_referer",
        "_wpcf7",
        "_wpcf7_version",
        "_wpcf7_locale",
        "_wpcf7_unit_tag",
        "_wpcf7_container_post",
        "_wpcf7_posted_data_hash",
        "action",
        "submit",
        "_client_masked",
        "wpforo_nonce",
        "_wpforo_",
    ];
    field.starts_with('_') || SYSTEM.iter().any(|s| field.contains(s))
}

/// Detect a PII type from a field name: exact names first, then substrings.
pub fn detect_by_field_name(field: &str) -> Option<&'static str> {
    let lower = field.to_ascii_lowercase();
    for (ptype, names) in FIELD_PATTERNS {
        if names.iter().any(|n| n.to_ascii_lowercase() == lower) {
            return Some(ptype);
        }
    }
    for (ptype, names) in FIELD_PATTERNS {
        if names
            .iter()
            .any(|n| lower.contains(&n.to_ascii_lowercase()))
        {
            return Some(ptype);
        }
    }
    None
}

pub fn detect_by_value(value: &str) -> Option<&'static str> {
    if is_email(value) {
        Some("email")
    } else if is_credit_card(value) {
        Some("card")
    } else if is_ssn(value) || is_mynumber(value) {
        Some("ssn")
    } else if is_ip_address(value) {
        Some("ip")
    } else if is_phone(value) {
        Some("phone")
    } else if is_url(value) {
        Some("url")
    } else if is_hosting_id(value) {
        Some("hosting")
    } else if is_ai_key(value) || is_token(value) {
        Some("token")
    } else {
        None
    }
}

pub fn detect_pii_type(field: &str, value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return None;
    }
    detect_by_field_name(field).or_else(|| detect_by_value(value))
}

pub fn is_email(value: &str) -> bool {
    EMAIL.is_match(value)
}

pub fn is_phone(value: &str) -> bool {
    let n = digits(value).len();
    (7..=15).contains(&n) && PHONE_PATTERNS.iter().any(|(_, p)| p.is_match(value))
}

pub fn is_credit_card(value: &str) -> bool {
    let d = digits(value);
    (13..=19).contains(&d.len()) && is_luhn_valid(&d)
}

pub fn is_ssn(value: &str) -> bool {
    SSN.is_match(value) && validate(Validate::IsSsnNumber, value)
}

pub fn is_mynumber(value: &str) -> bool {
    MYNUMBER.is_match(value) && is_mynumber_checkdigit(&digits(value))
}

pub fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok() || IPV4.is_match(value)
}

pub fn is_url(value: &str) -> bool {
    URL_FULL.is_match(value) || URL.is_match(value)
}

pub fn is_hosting_id(value: &str) -> bool {
    let len = value.len();
    if !(5..=50).contains(&len) {
        return false;
    }
    for (name, pattern) in HOSTING_PATTERNS.iter() {
        if !pattern.is_match(value) {
            continue;
        }
        match *name {
            "aws_account" => {
                if value.len() == 12 && digits(value).len() == 12 {
                    return true;
                }
            }
            "gcp_project" => {
                const COMMON: &[&str] = &[
                    "example", "default", "project", "website", "content", "message", "activity",
                ];
                if !COMMON.contains(&value.to_lowercase().as_str()) {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}

pub fn is_token(value: &str) -> bool {
    let len = value.len();
    len >= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        && unique_chars(value) as f64 / len as f64 > 0.3
}

/// Base confidence per PII type (used for scan reports).
pub fn confidence(ptype: &str) -> f64 {
    match ptype {
        "email" | "card" | "ip" => 0.95,
        "ssn" | "id_doc" => 0.90,
        "url" => 0.90,
        "hosting" | "password" | "contact" | "bank" => 0.85,
        "address" => 0.80,
        "dob" => 0.75,
        "phone" => 0.70,
        "token" | "name_text" => 0.60,
        "name" => 0.50,
        "custom" => 1.0,
        _ => 0.5,
    }
}
