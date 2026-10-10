use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;

use piip::config::{Settings, TEXT_TYPES};
use piip::engine::{Engine, EngineKind};
use piip::masker::{Finding, Masker};

/// PIIP: detect and mask personal information (PII) and secrets locally.
#[derive(Parser)]
#[command(name = "piip", version, about)]
struct Cli {
    #[command(flatten)]
    global: GlobalOpts,

    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct GlobalOpts {
    /// Config file (default: ./.piip.toml, then ~/.config/piip/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Detection engine: builtin (rule-based), presidio, or hybrid (both).
    #[arg(long, short = 'e', global = true)]
    engine: Option<String>,

    /// Presidio Analyzer URL.
    #[arg(long, global = true, env = "PIIP_PRESIDIO_URL")]
    presidio_url: Option<String>,

    /// Presidio language(s): auto, en, ja, or a comma-separated list.
    #[arg(long, global = true)]
    lang: Option<String>,

    /// Presidio minimum score (0-1).
    #[arg(long, global = true)]
    threshold: Option<f64>,

    /// Also mask these types (comma-separated), e.g. name_text.
    #[arg(long, global = true, value_name = "TYPES")]
    enable: Option<String>,

    /// Do not mask these types (comma-separated), e.g. ip,hosting.
    #[arg(long, global = true, value_name = "TYPES")]
    disable: Option<String>,

    /// Mask only these types (comma-separated).
    #[arg(long, global = true, value_name = "TYPES")]
    only: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Mask PII in text from files or stdin and print the result.
    Mask {
        /// Files to mask ("-" or none = stdin).
        files: Vec<PathBuf>,
        /// Rewrite the files in place.
        #[arg(long, short = 'i')]
        in_place: bool,
        /// Write the result to this file.
        #[arg(long, short = 'o', conflicts_with = "in_place")]
        output: Option<PathBuf>,
        /// Print JSON: {masked, changed, detected_types, consent_bypassed}.
        #[arg(long)]
        json: bool,
        /// Mask even when a consent phrase is present.
        #[arg(long)]
        ignore_consent: bool,
    },
    /// Scan files or directories for PII (dry run, nothing is changed).
    Scan {
        /// Files or directories (default: current directory; "-" = stdin).
        paths: Vec<PathBuf>,
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Include raw detected values in the output (they are PII!).
        #[arg(long)]
        show_values: bool,
        /// Exit with status 1 when PII is found.
        #[arg(long)]
        fail: bool,
        /// Include hidden files and directories.
        #[arg(long)]
        hidden: bool,
        /// Do not honor .gitignore/.ignore files.
        #[arg(long)]
        no_ignore: bool,
        /// Skip files larger than this many MiB.
        #[arg(long, default_value_t = 10)]
        max_size: u64,
    },
    /// Mask a JSON document: field names guide detection (like form data),
    /// other strings are masked as free text.
    MaskJson {
        /// JSON file ("-" or none = stdin).
        file: Option<PathBuf>,
        /// Pretty-print the output.
        #[arg(long)]
        pretty: bool,
    },
    /// Mask a single value as a named form field (e.g. password, email).
    Field { name: String, value: String },
    /// List PII types and whether they are masked with the current settings.
    Types,
    /// Check the Presidio backend.
    Presidio,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Format {
    Text,
    Json,
    Jsonl,
    Summary,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piip: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn load_settings(g: &GlobalOpts) -> Result<(Settings, EngineKind)> {
    let mut settings = Settings::load(g.config.as_deref())?;
    if let Some(url) = &g.presidio_url {
        settings.presidio.url = url.clone();
    }
    if let Some(lang) = &g.lang {
        settings.presidio.language = lang.clone();
    }
    if let Some(t) = g.threshold {
        settings.presidio.threshold = t;
    }
    if let Some(only) = &g.only {
        settings.only_types(only);
    }
    if let Some(list) = &g.enable {
        settings.set_types(list, true);
    }
    if let Some(list) = &g.disable {
        settings.set_types(list, false);
    }
    let engine = g
        .engine
        .clone()
        .or_else(|| std::env::var("PIIP_ENGINE").ok())
        .unwrap_or_else(|| settings.presidio.engine.clone())
        .parse()?;
    Ok((settings, engine))
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let (settings, kind) = load_settings(&cli.global)?;
    let engine = Engine::new(kind, &settings);

    match cli.command {
        Command::Mask {
            files,
            in_place,
            output,
            json,
            ignore_consent,
        } => cmd_mask(&engine, files, in_place, output, json, ignore_consent),
        Command::Scan {
            paths,
            format,
            show_values,
            fail,
            hidden,
            no_ignore,
            max_size,
        } => cmd_scan(
            &engine,
            paths,
            format,
            show_values,
            fail,
            hidden,
            no_ignore,
            max_size,
        ),
        Command::MaskJson { file, pretty } => cmd_mask_json(&engine, file, pretty),
        Command::Field { name, value } => {
            println!("{}", Masker::new(&settings).mask_value(&name, &value));
            Ok(ExitCode::SUCCESS)
        }
        Command::Types => {
            for (t, desc) in TEXT_TYPES {
                let on = if settings.should_mask_type(t) {
                    "on "
                } else {
                    "off"
                };
                println!("{on}  {t:<10} {desc}");
            }
            if kind != EngineKind::Builtin {
                println!("\nPresidio (-e {}):", format!("{kind:?}").to_lowercase());
                for (t, desc) in [
                    ("person", "PERSON: names found by NER"),
                    ("location", "LOCATION: place names — opt-in"),
                ] {
                    let on = if settings.should_mask_type(t) {
                        "on "
                    } else {
                        "off"
                    };
                    println!("{on}  {t:<10} {desc}");
                }
                println!(
                    "     other entities map to email phone card ip ssn bank id_doc token, or their lowercased name"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Presidio => {
            let client = piip::presidio::PresidioClient::new(settings.presidio.clone());
            println!("url:     {}", settings.presidio.url);
            println!("health:  {}", client.health()?);
            if let Some(langs) = client.supported_languages() {
                println!("languages: {}", langs.join(", "));
            }
            let sample = "My name is John Smith. 担当の山田太郎です。";
            for f in client.analyze(sample)? {
                println!(
                    "sample:  {:<14} {:.2}  {} -> {}",
                    f.provider.unwrap_or_default(),
                    f.score,
                    f.value,
                    f.masked
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_input(path: Option<&Path>) -> Result<String> {
    match path {
        None => read_stdin(),
        Some(p) if p.as_os_str() == "-" => read_stdin(),
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display())),
    }
}

fn read_stdin() -> Result<String> {
    let mut s = String::new();
    io::stdin()
        .read_to_string(&mut s)
        .context("reading stdin")?;
    Ok(s)
}

fn cmd_mask(
    engine: &Engine,
    files: Vec<PathBuf>,
    in_place: bool,
    output: Option<PathBuf>,
    json: bool,
    ignore_consent: bool,
) -> Result<ExitCode> {
    if in_place {
        if files.is_empty() || files.iter().any(|f| f.as_os_str() == "-") {
            bail!("--in-place needs file arguments");
        }
        for file in &files {
            let text = read_input(Some(file))?;
            let report = engine.mask(&text, ignore_consent, true)?;
            if report.consent_bypassed {
                eprintln!(
                    "piip: {}: consent phrase found, left unchanged",
                    file.display()
                );
            } else if report.changed {
                std::fs::write(file, &report.masked)
                    .with_context(|| format!("writing {}", file.display()))?;
                eprintln!(
                    "piip: {}: masked ({})",
                    file.display(),
                    report.detected_types.join(", ")
                );
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let inputs: Vec<Option<PathBuf>> = if files.is_empty() {
        vec![None]
    } else {
        files.into_iter().map(Some).collect()
    };
    let mut out = String::new();
    let mut reports = Vec::new();
    for input in &inputs {
        let text = read_input(input.as_deref())?;
        let report = engine.mask(&text, ignore_consent, json)?;
        if report.consent_bypassed {
            eprintln!(
                "piip: warning: a consent phrase was found: masking is bypassed for this text"
            );
        }
        out.push_str(&report.masked);
        reports.push(report);
    }

    let rendered = if json {
        let v = if reports.len() == 1 {
            serde_json::to_string_pretty(&reports[0])?
        } else {
            serde_json::to_string_pretty(&reports)?
        };
        v + "\n"
    } else {
        out
    };

    match output {
        Some(path) => std::fs::write(&path, rendered)
            .with_context(|| format!("writing {}", path.display()))?,
        None => io::stdout().write_all(rendered.as_bytes())?,
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Serialize)]
struct FileFinding<'a> {
    path: &'a str,
    line: usize,
    column: usize,
    #[serde(flatten)]
    finding: &'a Finding,
}

struct FileResult {
    path: String,
    findings: Vec<Finding>,
    positions: Vec<(usize, usize)>,
    consent: bool,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn cmd_scan(
    engine: &Engine,
    paths: Vec<PathBuf>,
    format: Format,
    show_values: bool,
    fail: bool,
    hidden: bool,
    no_ignore: bool,
    max_size: u64,
) -> Result<ExitCode> {
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths
    };

    let mut files: Vec<(String, Option<PathBuf>)> = Vec::new();
    for p in &paths {
        if p.as_os_str() == "-" {
            files.push(("<stdin>".into(), None));
            continue;
        }
        if p.is_file() {
            files.push((p.display().to_string(), Some(p.clone())));
            continue;
        }
        let walker = ignore::WalkBuilder::new(p)
            .hidden(!hidden)
            .ignore(!no_ignore)
            .git_ignore(!no_ignore)
            .git_global(!no_ignore)
            .git_exclude(!no_ignore)
            .build();
        for entry in walker {
            let entry = entry?;
            if entry.file_type().is_some_and(|t| t.is_file()) {
                let path = entry.into_path();
                files.push((path.display().to_string(), Some(path)));
            }
        }
    }

    let max_bytes = max_size * 1024 * 1024;
    let scan_one = |(label, path): &(String, Option<PathBuf>)| -> Option<FileResult> {
        let text = match path {
            None => read_stdin().ok()?,
            Some(p) => {
                let size = std::fs::metadata(p).map(|m| m.len()).ok()?;
                if size > max_bytes {
                    eprintln!(
                        "piip: {label}: skipped, larger than {max_size} MiB (see --max-size)"
                    );
                    return None;
                }
                let bytes = std::fs::read(p).ok()?;
                if bytes[..bytes.len().min(8192)].contains(&0) {
                    return None; // Binary file.
                }
                // Lossy: one stray byte must not hide a whole file's PII.
                String::from_utf8_lossy(&bytes).into_owned()
            }
        };
        let mut result = FileResult {
            path: label.clone(),
            findings: Vec::new(),
            positions: Vec::new(),
            consent: engine.settings.has_consent_phrase(&text),
            error: None,
        };
        match engine.scan(&text) {
            Ok(findings) => {
                result.positions = line_columns(&text, findings.iter().map(|f| f.start));
                result.findings = findings;
            }
            Err(e) => result.error = Some(format!("{e:#}")),
        }
        Some(result)
    };

    // Presidio is a single local server: keep request concurrency modest.
    let results: Vec<FileResult> = if engine.kind == EngineKind::Builtin {
        files.par_iter().filter_map(scan_one).collect()
    } else {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
        pool.install(|| files.par_iter().filter_map(scan_one).collect())
    };

    let mut stdout = io::stdout().lock();
    let mut total = 0;
    let mut files_with_pii = 0;
    let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();
    let mut all_json = Vec::new();

    for r in &results {
        if let Some(e) = &r.error {
            eprintln!("piip: {}: {e}", r.path);
        }
        if r.findings.is_empty() {
            continue;
        }
        files_with_pii += 1;
        for (f, &(line, column)) in r.findings.iter().zip(&r.positions) {
            total += 1;
            *by_type.entry(f.ptype.clone()).or_default() += 1;
            let mut shown = f.clone();
            if !show_values {
                shown.value = String::new();
            }
            match format {
                Format::Text => {
                    let provider = f
                        .provider
                        .as_deref()
                        .map(|p| format!(" ({p})"))
                        .unwrap_or_default();
                    let value = if show_values {
                        format!("  {:?}", f.value)
                    } else {
                        String::new()
                    };
                    writeln!(
                        stdout,
                        "{}:{line}:{column}: {}{provider} [{}] -> {}{value}",
                        r.path, f.ptype, f.rule, f.masked
                    )?;
                }
                Format::Jsonl => {
                    let row = FileFinding {
                        path: &r.path,
                        line,
                        column,
                        finding: &shown,
                    };
                    writeln!(stdout, "{}", serde_json::to_string(&row)?)?;
                }
                Format::Json => {
                    all_json.push(serde_json::to_value(FileFinding {
                        path: &r.path,
                        line,
                        column,
                        finding: &shown,
                    })?);
                }
                Format::Summary => {}
            }
        }
        if r.consent && format == Format::Text {
            writeln!(
                stdout,
                "{}: note: contains a consent phrase (mask would leave it unchanged)",
                r.path
            )?;
        }
    }

    match format {
        Format::Json => {
            let doc = serde_json::json!({
                "engine": format!("{:?}", engine.kind).to_lowercase(),
                "files_scanned": results.len(),
                "files_with_pii": files_with_pii,
                "total": total,
                "by_type": by_type,
                "findings": all_json,
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&doc)?)?;
        }
        Format::Summary | Format::Text => {
            if format == Format::Text && total > 0 {
                writeln!(stdout)?;
            }
            let types: Vec<String> = by_type.iter().map(|(t, n)| format!("{t}={n}")).collect();
            writeln!(
                stdout,
                "{total} finding(s) in {files_with_pii} of {} file(s){}{}",
                results.len(),
                if types.is_empty() { "" } else { ": " },
                types.join(" ")
            )?;
        }
        Format::Jsonl => {}
    }

    Ok(if fail && total > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// 1-based line and column (in characters) for each char offset.
fn line_columns(text: &str, offsets: impl Iterator<Item = usize>) -> Vec<(usize, usize)> {
    let mut line_starts = vec![0usize];
    for (i, c) in text.chars().enumerate() {
        if c == '\n' {
            line_starts.push(i + 1);
        }
    }
    offsets
        .map(|off| {
            let line = line_starts.partition_point(|&s| s <= off);
            (line, off - line_starts[line - 1] + 1)
        })
        .collect()
}

fn cmd_mask_json(engine: &Engine, file: Option<PathBuf>, pretty: bool) -> Result<ExitCode> {
    let text = read_input(file.as_deref())?;
    let mut doc: Value = serde_json::from_str(&text).context("parsing JSON")?;
    let masker = Masker::new(engine.settings);
    mask_json_value(engine, &masker, None, &mut doc)?;
    let out = if pretty {
        serde_json::to_string_pretty(&doc)?
    } else {
        serde_json::to_string(&doc)?
    };
    println!("{out}");
    Ok(ExitCode::SUCCESS)
}

fn mask_json_value(
    engine: &Engine,
    masker: &Masker,
    key: Option<&str>,
    value: &mut Value,
) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if piip::detector::is_system_field(k) {
                    continue;
                }
                mask_json_value(engine, masker, Some(k), v)?;
            }
        }
        Value::Array(items) => {
            for v in items {
                mask_json_value(engine, masker, key, v)?;
            }
        }
        Value::String(s) => {
            // A telling key (email, password, phone...) masks the whole value
            // like a form field; anything else is free text.
            let by_field = key
                .filter(|k| piip::detector::detect_by_field_name(k).is_some())
                .map(|k| masker.mask_value(k, s));
            *s = match by_field {
                Some(m) if m != *s => m,
                _ => engine.mask(s, false, false)?.masked,
            };
        }
        Value::Number(n) => {
            // Numbers under PII-ish keys (phone, card, account_id) as well.
            if let Some(k) = key {
                let raw = n.to_string();
                let m = masker.mask_value(k, &raw);
                if m != raw {
                    *value = Value::String(m);
                }
            }
        }
        _ => {}
    }
    Ok(())
}
