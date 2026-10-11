//! Checks on what leaves the model: PreToolUse (write-back of masked
//! values, personal data sent over the network) and UserPromptSubmit
//! (personal data typed or pasted into a prompt).

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::config::Settings;
use crate::engine::{Engine, EngineKind};
use crate::masker::Finding;

/// Masked values shown to the model, one file per session. Only masked
/// forms are stored (t***@example.jp), never the original values.
pub struct SessionState {
    dir: PathBuf,
}

impl SessionState {
    pub fn new() -> SessionState {
        let dir = std::env::var_os("PIIP_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| cache_dir().join("sessions"));
        SessionState { dir }
    }

    pub fn at(dir: &Path) -> SessionState {
        SessionState {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, session: &str) -> Option<PathBuf> {
        let safe: String = session
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        (!safe.is_empty()).then(|| self.dir.join(format!("{safe}.txt")))
    }

    pub fn record(&self, session: &str, tokens: &BTreeSet<String>) {
        let Some(path) = self.path(session) else {
            return;
        };
        if tokens.is_empty() || fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        if let Ok(mut f) = options.open(path) {
            let lines: String = tokens.iter().map(|t| format!("{t}\n")).collect();
            let _ = f.write_all(lines.as_bytes());
        }
        self.prune();
    }

    pub fn load(&self, session: &str) -> BTreeSet<String> {
        self.path(session)
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// Forget sessions untouched for a week.
    fn prune(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let week = std::time::Duration::from_secs(7 * 24 * 3600);
        for e in entries.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > week);
            if old {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::new()
    }
}

fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir)
        .join("piip")
}

pub struct Guard<'a> {
    settings: &'a Settings,
    engine: Engine<'a>,
}

impl<'a> Guard<'a> {
    /// Checks always use the builtin rules: they run before every tool call
    /// and prompt, so they must be fast and work without Presidio.
    pub fn new(settings: &'a Settings) -> Guard<'a> {
        Guard {
            settings,
            engine: Engine::new(EngineKind::Builtin, settings),
        }
    }

    /// PreToolUse: the hook output, or None to let the call through.
    pub fn pre_tool_use(&self, event: &Value, state: &SessionState) -> Option<Value> {
        let hook = &self.settings.hook;
        if !hook.enabled {
            return None;
        }
        let tool = event["tool_name"].as_str().unwrap_or_default();
        let input = &event["tool_input"];

        if hook.write_guard {
            let seen = state.load(event["session_id"].as_str().unwrap_or_default());
            let written = write_back(tool, input, &seen);
            if !written.is_empty() {
                let list: Vec<&str> = written.iter().map(String::as_str).take(5).collect();
                return Some(decision(
                    "deny",
                    &format!(
                        "piip: this would write masked values back ({}). They are not the real \
                         data (the model only saw them masked), so writing them would corrupt it. \
                         Leave those parts unchanged: edit around them, or ask the user to make \
                         this change.",
                        list.join(", ")
                    ),
                ));
            }
        }

        let action = hook.outbound.action.as_str();
        if action == "off" {
            return None;
        }
        let outgoing = match tool {
            "Bash" => {
                let command = input["command"].as_str().unwrap_or_default();
                sends_data(command, &hook.outbound.commands).then(|| command.to_string())
            }
            "WebFetch" | "WebSearch" => Some(strings(input)),
            t if t.starts_with("mcp__") => Some(strings(input)),
            _ => None,
        }?;
        let findings = self.findings(&outgoing, &hook.outbound.ignore_types);
        if findings.is_empty() {
            return None;
        }
        let where_to = if tool == "Bash" {
            "a network command"
        } else {
            tool
        };
        Some(decision(
            if action == "deny" { "deny" } else { "ask" },
            &format!(
                "piip: personal data would be sent out by {where_to}: {}.",
                summary(&findings)
            ),
        ))
    }

    /// UserPromptSubmit: the hook output, or None to send the prompt.
    pub fn user_prompt(&self, event: &Value) -> Option<Value> {
        let config = &self.settings.hook.prompt;
        if !self.settings.hook.enabled || config.action == "off" {
            return None;
        }
        let prompt = event["prompt"].as_str().unwrap_or_default();
        if !config.allow_marker.is_empty() && prompt.contains(&config.allow_marker) {
            return None;
        }
        let findings = self.findings(prompt, &config.ignore_types);
        if findings.is_empty() {
            return None;
        }
        let found = summary(&findings);
        if config.action == "warn" {
            return Some(json!({
                "systemMessage": format!("piip: the prompt contains personal data ({found}) and was sent as is."),
            }));
        }
        let masked = self
            .engine
            .mask(prompt, true, false)
            .map(|r| r.masked)
            .unwrap_or_default();
        let preview: String = masked.chars().take(2000).collect();
        let more = if masked.chars().count() > 2000 {
            "\n…"
        } else {
            ""
        };
        Some(json!({
            "decision": "block",
            "reason": format!(
                "piip: プロンプトに個人情報が含まれているため送信を止めました（{found}）。\n\
                 マスクした版を送るなら、次をコピーして送り直してください:\n\n{preview}{more}\n\n\
                 このまま送る場合は {} を付けて送り直してください。",
                config.allow_marker
            ),
        }))
    }

    fn findings(&self, text: &str, ignore: &[String]) -> Vec<Finding> {
        let mut findings = self.engine.scan(text).unwrap_or_default();
        findings.retain(|f| !ignore.contains(&f.ptype));
        findings
    }
}

fn decision(kind: &str, reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": reason,
        }
    })
}

/// "email ×2 (t***@example.jp), phone (***-***-5678)": types and masked
/// forms only, so the reason itself does not leak the values.
fn summary(findings: &[Finding]) -> String {
    let mut by_type: Vec<(String, Vec<&str>)> = Vec::new();
    for f in findings {
        match by_type.iter_mut().find(|(t, _)| *t == f.ptype) {
            Some((_, v)) => v.push(&f.masked),
            None => by_type.push((f.ptype.clone(), vec![&f.masked])),
        }
    }
    by_type
        .iter()
        .map(|(t, v)| {
            let n = if v.len() > 1 {
                format!(" ×{}", v.len())
            } else {
                String::new()
            };
            format!("{t}{n} ({})", v[0])
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Masked values that a tool call would add to a file or command.
pub fn write_back(tool: &str, input: &Value, seen: &BTreeSet<String>) -> Vec<String> {
    if seen.is_empty() {
        return Vec::new();
    }
    let pairs: Vec<(String, String)> = match tool {
        "Edit" => vec![(
            input["old_string"].as_str().unwrap_or_default().to_string(),
            input["new_string"].as_str().unwrap_or_default().to_string(),
        )],
        "MultiEdit" => input["edits"]
            .as_array()
            .map(|edits| {
                edits
                    .iter()
                    .map(|e| {
                        (
                            e["old_string"].as_str().unwrap_or_default().to_string(),
                            e["new_string"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        "Write" => {
            let path = input["file_path"].as_str().unwrap_or_default();
            let before = fs::read(path)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            vec![(
                before,
                input["content"].as_str().unwrap_or_default().to_string(),
            )]
        }
        "NotebookEdit" => vec![(
            String::new(),
            input["new_source"].as_str().unwrap_or_default().to_string(),
        )],
        "Bash" => vec![(
            String::new(),
            input["command"].as_str().unwrap_or_default().to_string(),
        )],
        _ => Vec::new(),
    };
    seen.iter()
        .filter(|t| {
            pairs
                .iter()
                .any(|(old, new)| new.matches(t.as_str()).count() > old.matches(t.as_str()).count())
        })
        .cloned()
        .collect()
}

/// Whether a shell command runs one of the network commands (as the first
/// word of a pipeline stage, after env assignments and sudo/env/xargs).
pub fn sends_data(command: &str, commands: &[String]) -> bool {
    command
        .split(['|', ';', '&', '\n', '(', ')', '`'])
        .filter_map(|stage| {
            stage.split_whitespace().find(|w| {
                !w.contains('=')
                    && !["sudo", "env", "xargs", "exec", "time", "nohup", "command"].contains(w)
            })
        })
        .map(|w| w.rsplit('/').next().unwrap_or(w))
        .any(|w| commands.iter().any(|c| c == w))
}

/// All string values of a JSON input, one per line.
fn strings(v: &Value) -> String {
    let mut out = String::new();
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => {
                out.push_str(s);
                out.push('\n');
            }
            Value::Array(a) => stack.extend(a.iter().rev()),
            Value::Object(m) => stack.extend(m.values().rev()),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen() -> BTreeSet<String> {
        ["t***@example.jp", "[REDACTED]"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn write_back_only_counts_new_occurrences() {
        let edit = json!({"old_string": "a", "new_string": "mail t***@example.jp"});
        assert_eq!(write_back("Edit", &edit, &seen()), vec!["t***@example.jp"]);
        let keep = json!({"old_string": "x [REDACTED] y", "new_string": "z [REDACTED] y"});
        assert!(write_back("Edit", &keep, &seen()).is_empty());
        let bash = json!({"command": "echo 'DB_PASSWORD=[REDACTED]' >> .env"});
        assert_eq!(write_back("Bash", &bash, &seen()), vec!["[REDACTED]"]);
        assert!(write_back("Edit", &edit, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn network_commands() {
        let c = crate::config::OutboundConfig::default().commands;
        assert!(sends_data("curl -X POST https://x -d @a.json", &c));
        assert!(sends_data("cat body.md | gh issue create -F -", &c));
        assert!(sends_data("FOO=1 sudo /usr/bin/curl x", &c));
        assert!(!sends_data("cargo test && git status", &c));
        assert!(!sends_data("echo curl", &c));
    }

    #[test]
    fn outbound_and_prompt() {
        let settings = Settings::default();
        let g = Guard::new(&settings);
        let state = SessionState::at(Path::new("/nonexistent-piip-state"));
        let send = json!({"tool_name": "Bash", "session_id": "s",
            "tool_input": {"command": "gh issue create --body 'contact taro@example.jp'"}});
        let out = g.pre_tool_use(&send, &state).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
        let reason = out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("t***@example.jp") && !reason.contains("taro@"));

        let local = json!({"tool_name": "Bash", "session_id": "s",
            "tool_input": {"command": "grep taro@example.jp users.csv"}});
        assert!(g.pre_tool_use(&local, &state).is_none());
        let ip_only = json!({"tool_name": "Bash", "session_id": "s",
            "tool_input": {"command": "ssh deploy@203.0.113.5"}});
        assert!(g.pre_tool_use(&ip_only, &state).is_none());

        let prompt = json!({"prompt": "この人に連絡して: taro@example.jp 090-1234-5678"});
        let out = g.user_prompt(&prompt).unwrap();
        assert_eq!(out["decision"], "block");
        let reason = out["reason"].as_str().unwrap();
        assert!(reason.contains("t***@example.jp") && !reason.contains("taro@"));
        assert!(
            g.user_prompt(&json!({"prompt": "taro@example.jp #piip-ok"}))
                .is_none()
        );
        assert!(
            g.user_prompt(&json!({"prompt": "テストを直して"}))
                .is_none()
        );
    }

    #[test]
    fn state_round_trip() {
        let dir = std::env::temp_dir().join(format!("piip-state-{}", std::process::id()));
        let state = SessionState::at(&dir);
        state.record("abc-1", &seen());
        assert_eq!(state.load("abc-1"), seen());
        assert!(state.load("../etc").is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
