//! Detection engines: builtin rules, Presidio, or both.

use std::str::FromStr;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::config::Settings;
use crate::masker::{Finding, Masker};
use crate::presidio::PresidioClient;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    /// Builtin rules only (fast, no dependencies).
    Builtin,
    /// Presidio only.
    Presidio,
    /// Builtin rules first, then Presidio NER on what is left.
    Hybrid,
}

impl FromStr for EngineKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "builtin" | "piip" => Ok(EngineKind::Builtin),
            "presidio" => Ok(EngineKind::Presidio),
            "hybrid" => Ok(EngineKind::Hybrid),
            other => bail!("unknown engine '{other}' (builtin, presidio, hybrid)"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MaskReport {
    pub masked: String,
    pub changed: bool,
    pub detected_types: Vec<String>,
    pub consent_bypassed: bool,
}

pub struct Engine<'a> {
    pub kind: EngineKind,
    pub settings: &'a Settings,
    pub presidio: Option<PresidioClient>,
}

impl<'a> Engine<'a> {
    pub fn new(kind: EngineKind, settings: &'a Settings) -> Self {
        let presidio =
            (kind != EngineKind::Builtin).then(|| PresidioClient::new(settings.presidio.clone()));
        Engine {
            kind,
            settings,
            presidio,
        }
    }

    fn masker(&self) -> Masker<'a> {
        Masker::new(self.settings)
    }

    fn presidio_findings(&self, text: &str) -> Result<Vec<Finding>> {
        let client = self.presidio.as_ref().expect("presidio client");
        let mut findings = client.analyze(text)?;
        findings.retain(|f| self.settings.should_mask_type(&f.ptype));
        Ok(findings)
    }

    /// Detect PII with positions in `text`.
    pub fn scan(&self, text: &str) -> Result<Vec<Finding>> {
        match self.kind {
            EngineKind::Builtin => Ok(self.masker().find_all(text)),
            EngineKind::Presidio => self.presidio_findings(text),
            EngineKind::Hybrid => {
                let mut findings = self.masker().find_all(text);
                for f in self.presidio_findings(text)? {
                    if !findings.iter().any(|b| f.start < b.end && b.start < f.end) {
                        findings.push(f);
                    }
                }
                findings.sort_by_key(|f| (f.start, f.end));
                Ok(findings)
            }
        }
    }

    /// Mask text. A consent phrase leaves the text unchanged unless
    /// `ignore_consent` is set. `detect_types` fills `detected_types`, which
    /// costs a second pass with the builtin engine.
    pub fn mask(&self, text: &str, ignore_consent: bool, detect_types: bool) -> Result<MaskReport> {
        let (masked, findings) = match self.kind {
            EngineKind::Builtin => {
                let findings = if detect_types {
                    self.masker().find_all(text)
                } else {
                    Vec::new()
                };
                (self.masker().mask_text(text), findings)
            }
            EngineKind::Presidio => {
                let findings = self.presidio_findings(text)?;
                (apply_findings(text, &findings), findings)
            }
            EngineKind::Hybrid => {
                // Builtin rules first; Presidio then sees the masked text, so
                // its spans cannot disturb the context the rules rely on.
                let builtin = self.masker().mask_text(text);
                let extra: Vec<Finding> = self
                    .presidio_findings(&builtin)?
                    .into_iter()
                    .filter(|f| !touches_mask(&builtin, f))
                    .collect();
                let mut findings = if detect_types {
                    self.masker().find_all(text)
                } else {
                    Vec::new()
                };
                let masked = apply_findings(&builtin, &extra);
                findings.extend(extra);
                (masked, findings)
            }
        };

        let mut detected_types: Vec<String> = findings.iter().map(|f| f.ptype.clone()).collect();
        detected_types.sort();
        detected_types.dedup();

        if !ignore_consent && self.settings.has_consent_phrase(text) {
            return Ok(MaskReport {
                masked: text.to_string(),
                changed: false,
                detected_types,
                consent_bypassed: true,
            });
        }

        Ok(MaskReport {
            changed: masked != text,
            masked,
            detected_types,
            consent_bypassed: false,
        })
    }
}

/// Spans that contain or border an existing mask ("東京都***") are left
/// alone, so deliberate partial masks are kept.
fn touches_mask(text: &str, f: &Finding) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let lo = f.start.saturating_sub(1);
    let hi = (f.end + 1).min(chars.len());
    let around: String = chars[lo..hi].iter().collect();
    around.contains('*') || around.contains("[REDACTED]")
}

/// Replace non-overlapping char-offset findings with their masked values.
pub fn apply_findings(text: &str, findings: &[Finding]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| f.start);

    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for f in sorted {
        if f.start < pos || f.end > chars.len() {
            continue;
        }
        out.extend(&chars[pos..f.start]);
        out.push_str(&f.masked);
        pos = f.end;
    }
    out.extend(&chars[pos..]);
    out
}
