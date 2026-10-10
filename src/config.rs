//! Settings: enabled types, consent phrases, custom patterns, Presidio.
//!
//! Looked up in order: --config, ./.piip.toml, $XDG_CONFIG_HOME/piip/config.toml
//! (~/.config/piip/config.toml). Every key is optional.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::regex::Re;

/// Consent phrases used when the config does not set `consent_phrases`.
pub const DEFAULT_CONSENT_PHRASES: &[&str] = &[
    "マスクを外すことに同意",
    "個人情報の公開に同意します",
    "I consent to unmasking",
    "I consent to sharing my personal information",
];

/// PII types that are masked only when explicitly enabled. A bare place
/// name (Presidio LOCATION: 東京都, Seattle) is not personal data on its own,
/// so "東京都に行きました" is left alone.
pub const DEFAULT_OFF_TYPES: &[&str] = &["name_text", "location"];

/// Types of the free-text rules, for listings.
pub const TEXT_TYPES: &[(&str, &str)] = &[
    (
        "email",
        "Email addresses (taro@example.jp → t***@example.jp)",
    ),
    (
        "phone",
        "Phone numbers: JP mobile/landline/toll-free, international, US",
    ),
    (
        "address",
        "Japanese street addresses and labeled postal codes (〒)",
    ),
    ("card", "Payment card numbers (Luhn-validated)"),
    ("ssn", "US SSN / Japanese My Number (check digit validated)"),
    ("password", "Labeled passwords and PASSWORD=… config values"),
    (
        "token",
        "API keys, developer secrets, private keys, Basic/Bearer credentials",
    ),
    (
        "hosting",
        "Hosting account/server IDs (Xserver, Sakura, ConoHa, Azure GUID…)",
    ),
    ("ip", "IPv4 and IPv6 addresses"),
    ("dob", "Labeled dates of birth (生年月日: …)"),
    (
        "bank",
        "Labeled bank account numbers (口座番号 / 普通 1234567)",
    ),
    (
        "contact",
        "Labeled inquiry-style fields (お名前/住所/電話/会員ID/有効期限/CVV)",
    ),
    (
        "id_doc",
        "Labeled ID documents (passport, license, insurance, pension, residence card)",
    ),
    (
        "name_text",
        "Names in self-introductions (山田太郎と申します) — opt-in",
    ),
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// mask_<type> switches, e.g. `[types] name_text = true`.
    #[serde(default)]
    pub types: BTreeMap<String, bool>,
    /// None = defaults; [] = no phrase bypasses masking.
    pub consent_phrases: Option<Vec<String>>,
    #[serde(default)]
    pub custom_patterns: Vec<CustomPatternConfig>,
    #[serde(default)]
    pub presidio: PresidioConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomPatternConfig {
    pub label: Option<String>,
    /// Regex without delimiters (PCRE, Unicode mode).
    pub pattern: String,
    pub replacement: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PresidioConfig {
    /// builtin | presidio | hybrid
    pub engine: String,
    pub url: String,
    /// auto | comma-separated language codes (en,ja)
    pub language: String,
    pub threshold: f64,
    /// Only these entities (empty = all except `exclude_entities`).
    pub entities: Vec<String>,
    pub exclude_entities: Vec<String>,
    pub timeout_secs: u64,
}

impl Default for PresidioConfig {
    fn default() -> Self {
        PresidioConfig {
            engine: "builtin".into(),
            url: "http://127.0.0.1:5002".into(),
            language: "auto".into(),
            threshold: 0.5,
            entities: Vec::new(),
            exclude_entities: vec![
                "DATE_TIME".into(),
                "NRP".into(),
                "URL".into(),
                "ORGANIZATION".into(),
                "IN_PAN".into(),
            ],
            timeout_secs: 60,
        }
    }
}

pub struct CustomPattern {
    pub label: String,
    pub re: Re,
    pub replacement: String,
}

pub struct Settings {
    pub types: BTreeMap<String, bool>,
    pub consent_phrases: Vec<String>,
    pub custom_patterns: Vec<CustomPattern>,
    pub presidio: PresidioConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Settings::from_file_config(FileConfig::default()).expect("default config is valid")
    }
}

impl Settings {
    pub fn load(explicit: Option<&Path>) -> Result<Settings> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => default_config_paths().into_iter().find(|p| p.is_file()),
        };
        let file = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => FileConfig::default(),
        };
        Settings::from_file_config(file)
    }

    pub fn from_file_config(file: FileConfig) -> Result<Settings> {
        let consent_phrases = match file.consent_phrases {
            Some(list) => list.into_iter().filter(|p| !p.is_empty()).collect(),
            None => DEFAULT_CONSENT_PHRASES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };

        let mut custom_patterns = Vec::new();
        for row in file
            .custom_patterns
            .into_iter()
            .filter(|r| r.enabled && !r.pattern.is_empty())
        {
            let re =
                Re::unicode(&row.pattern).map_err(|e| anyhow::anyhow!("custom pattern: {e}"))?;
            let replacement = row
                .replacement
                .map(|r| sanitize_replacement(&r))
                .filter(|r| !r.is_empty());
            custom_patterns.push(CustomPattern {
                label: row
                    .label
                    .filter(|l| !l.is_empty())
                    .unwrap_or_else(|| "Custom pattern".into()),
                re,
                replacement: replacement.unwrap_or_else(|| "***".into()),
            });
        }

        Ok(Settings {
            types: file.types,
            consent_phrases,
            custom_patterns,
            presidio: file.presidio,
        })
    }

    /// An explicit setting always wins; otherwise all types except the
    /// opt-in ones are masked.
    pub fn should_mask_type(&self, ptype: &str) -> bool {
        match self.types.get(ptype) {
            Some(v) => *v,
            None => !DEFAULT_OFF_TYPES.contains(&ptype),
        }
    }

    pub fn set_types(&mut self, list: &str, value: bool) {
        for t in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            self.types.insert(t.to_string(), value);
        }
    }

    /// Mask only these types.
    pub fn only_types(&mut self, list: &str) {
        let keep: Vec<&str> = list
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        let mut all: Vec<&str> = TEXT_TYPES.iter().map(|(t, _)| *t).collect();
        all.extend(["name", "url", "custom", "person", "location"]);
        for t in all {
            self.types.insert(t.to_string(), keep.contains(&t));
        }
        for t in keep {
            self.types.insert(t.to_string(), true);
        }
    }

    /// Case-insensitive (Unicode) consent phrase check.
    pub fn has_consent_phrase(&self, text: &str) -> bool {
        if self.consent_phrases.is_empty() {
            return false;
        }
        let lower = text.to_lowercase();
        self.consent_phrases
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
    }
}

/// Remove characters that could break out of HTML from a replacement.
pub fn sanitize_replacement(replacement: &str) -> String {
    replacement
        .chars()
        .filter(|c| !"<>\"'`".contains(*c))
        .collect()
}

pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(".piip.toml")];
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        paths.push(PathBuf::from(dir).join("piip/config.toml"));
    } else if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".config/piip/config.toml"));
    }
    paths
}
