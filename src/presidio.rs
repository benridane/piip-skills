//! Microsoft Presidio Analyzer backend.
//!
//! Talks to the Presidio Analyzer REST API (`POST /analyze`), either the
//! official container (English) or the bundled `presidio/server.py`
//! (English + Japanese spaCy models). Presidio adds NER-based detection
//! (PERSON, LOCATION, ...) on top of the builtin rules; anonymization itself
//! stays in Rust so masks look the same as builtin ones.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::config::PresidioConfig;
use crate::masker::{self, Finding};

#[derive(Debug, Deserialize)]
struct AnalyzerResult {
    entity_type: String,
    start: usize,
    end: usize,
    score: f64,
}

#[derive(Serialize)]
struct AnalyzeRequest<'a> {
    text: &'a str,
    language: &'a str,
    score_threshold: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    entities: Option<&'a [String]>,
}

pub struct PresidioClient {
    cfg: PresidioConfig,
    agent: ureq::Agent,
}

impl PresidioClient {
    pub fn new(cfg: PresidioConfig) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .build();
        PresidioClient { cfg, agent }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cfg.url.trim_end_matches('/'), path)
    }

    pub fn health(&self) -> Result<String> {
        let res = self
            .agent
            .get(&self.url("/health"))
            .call()
            .map_err(|e| anyhow!("Presidio is not reachable at {}: {e}", self.cfg.url))?;
        Ok(res.into_string()?.trim().to_string())
    }

    /// Languages supported by the server (bundled server only; the
    /// official container has no such endpoint).
    pub fn supported_languages(&self) -> Option<Vec<String>> {
        self.agent
            .get(&self.url("/supportedlanguages"))
            .call()
            .ok()?
            .into_json()
            .ok()
    }

    /// Analyze text and return non-overlapping findings (char offsets).
    pub fn analyze(&self, text: &str) -> Result<Vec<Finding>> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let languages = resolve_languages(&self.cfg.language, text);
        let chars: Vec<char> = text.chars().collect();
        let mut raw: Vec<AnalyzerResult> = Vec::new();
        let mut errors = Vec::new();

        // spaCy's Japanese tokenizer (Sudachi) rejects inputs over 49149
        // bytes, so long texts go in line-aligned chunks.
        let chunks = chunk_text(text, CHUNK_BYTES);
        let entities = (!self.cfg.entities.is_empty()).then_some(self.cfg.entities.as_slice());
        let mut failed_langs = 0;

        for lang in &languages {
            let mut lang_error = None;
            for (char_offset, chunk) in &chunks {
                if chunk.trim().is_empty() {
                    continue;
                }
                let request = AnalyzeRequest {
                    text: chunk,
                    language: lang,
                    score_threshold: self.cfg.threshold,
                    entities,
                };
                match self.agent.post(&self.url("/analyze")).send_json(&request) {
                    Ok(res) => {
                        let results = res.into_json::<Vec<AnalyzerResult>>()?;
                        raw.extend(results.into_iter().filter_map(|mut r| {
                            r.start += char_offset;
                            r.end += char_offset;
                            tidy_span(&chars, lang, r)
                        }));
                    }
                    Err(ureq::Error::Status(code, res)) => {
                        let body = res.into_string().unwrap_or_default();
                        lang_error = Some(format!("[{lang}] HTTP {code}: {}", body.trim()));
                        break;
                    }
                    Err(e) => bail!("Presidio is not reachable at {}: {e}", self.cfg.url),
                }
            }
            if let Some(e) = lang_error {
                failed_langs += 1;
                errors.push(e);
            }
        }

        if raw.is_empty() && failed_langs == languages.len() {
            bail!("Presidio analyze failed: {}", errors.join("; "));
        }
        for e in &errors {
            eprintln!("piip: warning: Presidio skipped a language: {e}");
        }

        raw.retain(|r| {
            r.score >= self.cfg.threshold
                && !self
                    .cfg
                    .exclude_entities
                    .iter()
                    .any(|e| e == &r.entity_type)
        });

        // Highest score first, then longest; keep non-overlapping spans.
        raw.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
        });
        let mut findings: Vec<Finding> = Vec::new();
        for r in raw {
            if findings.iter().any(|f| r.start < f.end && f.start < r.end) {
                continue;
            }
            let value: String = chars[r.start..r.end].iter().collect();
            let ptype = entity_type_to_piip(&r.entity_type);
            findings.push(Finding {
                source: "presidio",
                rule: format!("presidio:{}", r.entity_type),
                ptype: ptype.to_string(),
                provider: Some(r.entity_type.clone()),
                start: r.start,
                end: r.end,
                score: (r.score * 100.0).round() / 100.0,
                masked: mask_entity(&r.entity_type, &value),
                value,
            });
        }
        findings.sort_by_key(|f| f.start);
        Ok(findings)
    }
}

/// Request size per call, well under Sudachi's 49149-byte limit.
const CHUNK_BYTES: usize = 32 * 1024;

/// Split text into chunks of at most `max` bytes, at line ends where
/// possible. Returns (char offset, chunk) pairs.
fn chunk_text(text: &str, max: usize) -> Vec<(usize, &str)> {
    let mut chunks = Vec::new();
    let mut start = 0; // Byte offset.
    let mut char_offset = 0;
    while start < text.len() {
        let mut end = (start + max).min(text.len());
        if end < text.len() {
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            if let Some(nl) = text[start..end].rfind('\n')
                && nl > 0
            {
                end = start + nl + 1;
            }
        }
        let chunk = &text[start..end];
        chunks.push((char_offset, chunk));
        char_offset += chunk.chars().count();
        start = end;
    }
    chunks
}

fn is_japanese(c: char) -> bool {
    matches!(c as u32, 0x3000..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xFF00..=0xFFEF)
}

/// Trim whitespace and punctuation from span edges, and cut spans from the
/// English model where they run into Japanese text ("John Smith. 担当").
fn tidy_span(chars: &[char], lang: &str, mut r: AnalyzerResult) -> Option<AnalyzerResult> {
    if r.start >= r.end || r.end > chars.len() {
        return None;
    }
    if lang != "ja"
        && let Some(i) = chars[r.start..r.end].iter().position(|&c| is_japanese(c))
    {
        r.end = r.start + i;
    }
    // Any model: a switch between Latin and Japanese across a separator
    // ends the entity (the Japanese model also returns "John Smith. 担当").
    let sep = |c: char| c.is_whitespace() || ".,!?。、！？".contains(c);
    let mut last_script: Option<bool> = None;
    let mut sep_start: Option<usize> = None;
    for (i, &c) in chars.iter().enumerate().take(r.end).skip(r.start) {
        if sep(c) {
            sep_start.get_or_insert(i);
            continue;
        }
        let script = is_japanese(c);
        if let (Some(prev), Some(cut)) = (last_script, sep_start)
            && prev != script
        {
            r.end = cut;
            break;
        }
        last_script = Some(script);
        sep_start = None;
    }
    let edge = |c: char| {
        c.is_whitespace()
            || (c.is_ascii_punctuation() && !"+(".contains(c))
            || "、。・「」『』（）".contains(c)
    };
    while r.start < r.end && edge(chars[r.end - 1]) && !matches!(chars[r.end - 1], ')' | ']') {
        r.end -= 1;
    }
    while r.start < r.end && edge(chars[r.start]) && chars[r.start] != '+' {
        r.start += 1;
    }
    (r.start < r.end).then_some(r)
}

/// "auto": ja when the text has kana/kanji, en when it has Latin words.
pub fn resolve_languages(setting: &str, text: &str) -> Vec<String> {
    if setting != "auto" {
        return setting
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    let has_japanese = text.chars().any(|c| {
        matches!(c as u32, 0x3041..=0x3096 | 0x30A1..=0x30FA | 0x3400..=0x4DBF | 0x4E00..=0x9FFF)
    });
    let latin_words = text
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| w.len() >= 2)
        .count();

    let mut langs = Vec::new();
    if has_japanese {
        langs.push("ja".to_string());
    }
    if latin_words >= 2 || langs.is_empty() {
        langs.push("en".to_string());
    }
    langs
}

/// Map Presidio entities onto piip types where they overlap, so the same
/// `--enable/--disable` switches apply.
pub fn entity_type_to_piip(entity: &str) -> String {
    match entity {
        "EMAIL_ADDRESS" => "email".into(),
        "PHONE_NUMBER" => "phone".into(),
        "CREDIT_CARD" => "card".into(),
        "IP_ADDRESS" => "ip".into(),
        "US_SSN" | "US_ITIN" => "ssn".into(),
        "IBAN_CODE" | "US_BANK_NUMBER" => "bank".into(),
        "US_PASSPORT" | "US_DRIVER_LICENSE" | "UK_NHS" | "MEDICAL_LICENSE" => "id_doc".into(),
        "CRYPTO" => "token".into(),
        "PERSON" => "person".into(),
        "LOCATION" => "location".into(),
        other => other.to_ascii_lowercase(),
    }
}

fn mask_entity(entity: &str, value: &str) -> String {
    match entity {
        "EMAIL_ADDRESS" => masker::mask_email(value),
        "PHONE_NUMBER" => masker::mask_phone(value),
        "CREDIT_CARD" => masker::mask_credit_card(value),
        "IP_ADDRESS" => masker::mask_ip(value),
        "US_SSN" => masker::mask_ssn(value),
        "PERSON" => masker::mask_person_name(value),
        _ => "***".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_cover_text_on_line_ends() {
        let text = "あいう\nえお\nかきくけこ\n".repeat(50);
        let chunks = chunk_text(&text, 64);
        assert!(chunks.iter().all(|(_, c)| c.len() <= 64));
        assert!(chunks.iter().all(|(_, c)| c.ends_with('\n')));
        assert_eq!(chunks.iter().map(|(_, c)| *c).collect::<String>(), text);
        let (off, c) = chunks[1];
        assert_eq!(
            text.chars().skip(off).take(3).collect::<String>(),
            c.chars().take(3).collect::<String>()
        );
    }

    #[test]
    fn auto_language() {
        assert_eq!(resolve_languages("auto", "山田太郎です"), vec!["ja"]);
        assert_eq!(resolve_languages("auto", "My name is John"), vec!["en"]);
        assert_eq!(
            resolve_languages("auto", "担当は John Smith です"),
            vec!["ja", "en"]
        );
        assert_eq!(resolve_languages("en, ja", "x"), vec!["en", "ja"]);
    }
}
