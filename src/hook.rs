//! Claude Code PostToolUse hook: mask what Read, Grep and Bash return
//! before the model sees it. (PreToolUse and UserPromptSubmit checks live
//! in `crate::guard`.)
//!
//! The hook gets the tool result on stdin and answers with
//! `hookSpecificOutput.updatedToolOutput`, so files on disk are never
//! touched. Edits keep working on unmasked text; an Edit whose old_string
//! contains a masked span simply fails to match.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::{Value, json};

use crate::config::{HookConfig, Settings};
use crate::engine::{Engine, EngineKind};

pub struct Hook<'a> {
    config: &'a HookConfig,
    include: GlobSet,
    exclude: GlobSet,
    engine: Engine<'a>,
    fallback: Option<Engine<'a>>,
}

/// What the hook did to one tool result.
#[derive(Debug, Default, PartialEq)]
pub struct Outcome {
    pub response: Option<Value>,
    pub types: BTreeSet<String>,
    pub notes: Vec<String>,
    /// Masked values the model was shown (t***@example.jp), for the
    /// write-back guard.
    pub tokens: BTreeSet<String>,
}

impl<'a> Hook<'a> {
    pub fn new(settings: &'a Settings) -> Result<Hook<'a>> {
        let config = &settings.hook;
        let kind: EngineKind = config.engine.parse()?;
        Ok(Hook {
            config,
            include: glob_set(&config.include)?,
            exclude: glob_set(&config.exclude)?,
            engine: Engine::new(kind, settings),
            fallback: (kind != EngineKind::Builtin)
                .then(|| Engine::new(EngineKind::Builtin, settings)),
        })
    }

    /// Whether a file's contents are masked.
    pub fn covers(&self, path: &str) -> bool {
        let p = Path::new(path);
        let name = p.file_name().map(Path::new);
        let hit = |set: &GlobSet| set.is_match(p) || name.is_some_and(|n| set.is_match(n));
        !hit(&self.exclude) && (self.config.all_files || hit(&self.include))
    }

    /// Handle one hook event (the JSON Claude Code writes on stdin).
    pub fn handle(&self, event: &Value) -> Outcome {
        let mut out = Outcome::default();
        if !self.config.enabled {
            return out;
        }
        let tool = event["tool_name"].as_str().unwrap_or_default();
        let input = &event["tool_input"];
        let mut response = event["tool_response"].clone();
        let changed = match tool {
            "Read" => self.read(input, &mut response, &mut out),
            "Grep" if self.config.grep => self.grep(input, &mut response, &mut out),
            "Bash" if self.config.bash => self.bash(input, &mut response, &mut out),
            _ => false,
        };
        if changed {
            out.response = Some(response);
        }
        out
    }

    fn read(&self, input: &Value, response: &mut Value, out: &mut Outcome) -> bool {
        let path = input["file_path"].as_str().unwrap_or_default();
        if response["type"] != "text" || !self.covers(path) {
            return false;
        }
        self.mask_field(&mut response["file"]["content"], out)
    }

    fn grep(&self, input: &Value, response: &mut Value, out: &mut Outcome) -> bool {
        if response["mode"] != "content" {
            return false;
        }
        let Some(content) = response["content"].as_str() else {
            return false;
        };
        // A single-file search prints "N:text"; otherwise "path:N:text".
        let target = input["path"].as_str().unwrap_or_default();
        let single = Path::new(target).is_file();
        if single && !self.covers(target) {
            return false;
        }
        let mut lines = Vec::new();
        let mut changed = false;
        for line in content.split('\n') {
            let (prefix, rest) = if single {
                ("", line)
            } else {
                match line.split_once(':') {
                    Some((path, rest)) if self.covers(path) => (path, rest),
                    _ => {
                        lines.push(line.to_string());
                        continue;
                    }
                }
            };
            let masked = self.mask_text(rest, out);
            changed |= masked != rest;
            lines.push(if single {
                masked
            } else {
                format!("{prefix}:{masked}")
            });
        }
        if changed {
            response["content"] = Value::String(lines.join("\n"));
        }
        changed
    }

    fn bash(&self, input: &Value, response: &mut Value, out: &mut Outcome) -> bool {
        let command = input["command"].as_str().unwrap_or_default();
        if !command_names_covered_file(command, |p| self.covers(p)) {
            return false;
        }
        let a = self.mask_field(&mut response["stdout"], out);
        let b = self.mask_field(&mut response["stderr"], out);
        a || b
    }

    fn mask_field(&self, field: &mut Value, out: &mut Outcome) -> bool {
        let Some(text) = field.as_str() else {
            return false;
        };
        let masked = self.mask_text(text, out);
        if masked == text {
            return false;
        }
        *field = Value::String(masked);
        true
    }

    /// Mask with the hook engine. Consent phrases are ignored: the text is
    /// headed to a model, not shown back to the person who consented. If
    /// masking fails the text is withheld rather than passed through.
    fn mask_text(&self, text: &str, out: &mut Outcome) -> String {
        let mut result = self.engine.mask(text, true, true);
        if let (Err(e), Some(fallback)) = (&result, &self.fallback) {
            let note = format!("Presidio unavailable ({e:#}); used builtin rules");
            if !out.notes.contains(&note) {
                out.notes.push(note);
            }
            result = fallback.mask(text, true, true);
        }
        match result {
            Ok(report) => {
                out.types.extend(report.detected_types);
                out.tokens.extend(masked_tokens(text, &report.masked));
                report.masked
            }
            Err(e) => {
                out.notes.push(format!("masking failed: {e:#}"));
                "[piip: output withheld because masking failed]".into()
            }
        }
    }
}

/// The JSON a PostToolUse hook prints, or None to leave the result alone.
pub fn hook_output(outcome: &Outcome) -> Option<Value> {
    let response = outcome.response.as_ref()?;
    let types: Vec<&str> = outcome.types.iter().map(String::as_str).collect();
    let mut context = format!(
        "piip masked personal data/secrets in this tool output ({}). Masked spans such as \
         t***@example.jp, ***-***-5678 or [REDACTED] are not the real values: never write them \
         back with Edit or Write, and edit around them instead. The file on disk is unchanged.",
        if types.is_empty() {
            "custom".to_string()
        } else {
            types.join(", ")
        }
    );
    for note in &outcome.notes {
        context.push_str(&format!(" Note: {note}."));
    }
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": response,
            "additionalContext": context,
        }
    }))
}

/// Words of the masked text that carry a mask and were not in the original
/// (t***@example.jp, ***-***-5678, 東京都***, [REDACTED]). Words shorter
/// than five characters (山*, ***) are too common to guard on.
pub fn masked_tokens(original: &str, masked: &str) -> BTreeSet<String> {
    masked
        .split(|c: char| c.is_whitespace() || "\"'`=:,;()<>{}|".contains(c))
        .filter(|w| w.chars().count() >= 5)
        .filter(|w| w.contains("[REDACTED]") || (w.contains('*') && w.chars().any(|c| c != '*')))
        .filter(|w| !original.contains(*w))
        .map(str::to_string)
        .collect()
}

/// Whether a shell command names a file the hook covers (cat app.log,
/// tail -f logs/*.log, grep x users.csv ...). A heuristic: it looks at
/// words that look like file names.
pub fn command_names_covered_file(command: &str, covers: impl Fn(&str) -> bool) -> bool {
    command
        .split(|c: char| c.is_whitespace() || "|;&<>()`$".contains(c))
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
        .filter(|w| !w.is_empty() && !w.starts_with('-'))
        .filter(|w| w.contains('.') && !w.contains("://"))
        .any(|w| covers(w.split_once('=').map_or(w, |(_, v)| v)))
}

fn glob_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        match Glob::new(p) {
            Ok(g) => {
                builder.add(g);
            }
            Err(e) => bail!("hook glob {p:?}: {e}"),
        }
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook_settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn covers_data_files_not_source() {
        let s = hook_settings();
        let h = Hook::new(&s).unwrap();
        assert!(h.covers("/srv/app/logs/access.log"));
        assert!(h.covers("/srv/app/logs/access.log.1"));
        assert!(h.covers("users.csv"));
        assert!(h.covers("/srv/app/.env"));
        assert!(h.covers("/srv/app/.env.production"));
        assert!(!h.covers("/srv/app/src/main.rs"));
        assert!(!h.covers("/srv/app/package.json"));
        assert!(!h.covers("/srv/app/node_modules/x/data.json"));
    }

    #[test]
    fn read_is_masked() {
        let s = hook_settings();
        let h = Hook::new(&s).unwrap();
        let event = json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/x/inquiry.txt"},
            "tool_response": {"type": "text", "file": {
                "filePath": "/x/inquiry.txt",
                "content": "email taro@example.jp\nok\n", "numLines": 3}},
        });
        let out = h.handle(&event);
        let r = out.response.unwrap();
        assert_eq!(r["file"]["content"], "email t***@example.jp\nok\n");
        assert_eq!(r["file"]["numLines"], 3);
        assert!(out.types.contains("email"));
        assert!(out.tokens.contains("t***@example.jp"));
    }

    #[test]
    fn source_read_and_clean_data_untouched() {
        let s = hook_settings();
        let h = Hook::new(&s).unwrap();
        let mut event = json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/x/main.rs"},
            "tool_response": {"type": "text", "file": {"content": "// taro@example.jp"}},
        });
        assert_eq!(h.handle(&event), Outcome::default());
        event["tool_input"]["file_path"] = json!("/x/notes.txt");
        event["tool_response"]["file"]["content"] = json!("nothing here");
        assert_eq!(h.handle(&event), Outcome::default());
    }

    #[test]
    fn grep_lines_from_covered_files() {
        let s = hook_settings();
        let h = Hook::new(&s).unwrap();
        let event = json!({
            "tool_name": "Grep",
            "tool_input": {"pattern": "example", "path": "/nonexistent-dir", "output_mode": "content"},
            "tool_response": {"mode": "content",
                "content": "a.log:2:mail taro@example.jp\nsrc/x.rs:9:taro@example.jp"},
        });
        let r = h.handle(&event).response.unwrap();
        assert_eq!(
            r["content"],
            "a.log:2:mail t***@example.jp\nsrc/x.rs:9:taro@example.jp"
        );
    }

    #[test]
    fn bash_output_when_command_reads_data() {
        let s = hook_settings();
        let h = Hook::new(&s).unwrap();
        let mut event = json!({
            "tool_name": "Bash",
            "tool_input": {"command": "tail -n 5 logs/app.log | grep -v debug"},
            "tool_response": {"stdout": "login taro@example.jp", "stderr": ""},
        });
        let r = h.handle(&event).response.unwrap();
        assert_eq!(r["stdout"], "login t***@example.jp");
        event["tool_input"]["command"] = json!("git log -1");
        assert!(h.handle(&event).response.is_none());
    }

    #[test]
    fn command_heuristic() {
        let covers = |p: &str| p.ends_with(".log") || p.ends_with(".csv");
        assert!(command_names_covered_file("cat 'my file.csv'", covers));
        assert!(command_names_covered_file(
            "head -n3 </var/log/x.log",
            covers
        ));
        assert!(command_names_covered_file("cut -d, -f1 data/*.csv", covers));
        assert!(!command_names_covered_file("cargo test --release", covers));
        assert!(!command_names_covered_file(
            "curl https://example.com/a.log",
            covers
        ));
    }
}
