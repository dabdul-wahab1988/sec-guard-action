mod models;

use git2::Repository;
use models::{Finding, Report, ScanError, ScanSummary, Severity};
use regex::Regex;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tree_sitter::Parser;

const MAX_FILE_BYTES: u64 = 1_000_000;
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".sec-guard",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "vendor",
];
const TEXT_EXTENSIONS: &[&str] = &[
    "bash",
    "c",
    "cfg",
    "conf",
    "cpp",
    "css",
    "dockerfile",
    "env",
    "go",
    "h",
    "hcl",
    "hpp",
    "html",
    "ini",
    "java",
    "js",
    "json",
    "jsx",
    "lock",
    "md",
    "php",
    "properties",
    "ps1",
    "py",
    "rb",
    "rs",
    "sh",
    "sql",
    "tf",
    "toml",
    "ts",
    "tsx",
    "txt",
    "xml",
    "yaml",
    "yml",
];

struct Rule {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    description: &'static str,
    remediation: &'static str,
    pattern: Regex,
    redact_evidence: bool,
}

struct Config {
    workspace: PathBuf,
    output: PathBuf,
    sarif_output: PathBuf,
    severity_threshold: Severity,
    ignore_file: PathBuf,
}

struct IgnoreMatcher {
    patterns: Vec<Regex>,
}

struct ScanState<'a> {
    root: &'a Path,
    rules: &'a [Rule],
    ignores: &'a IgnoreMatcher,
    ignore_file: &'a Path,
    syntax_parser: &'a mut Parser,
    findings: &'a mut Vec<Finding>,
    scan_summary: &'a mut ScanSummary,
}

fn main() {
    match try_main() {
        Ok(exit_code) => {
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(error) => {
            eprintln!("sec-guard-core: {error}");
            std::process::exit(2);
        }
    }
}

fn try_main() -> Result<i32, Box<dyn Error>> {
    if env::args().any(|argument| argument == "--help" || argument == "-h") {
        print_usage();
        return Ok(0);
    }

    let config = Config::from_args()?;
    let rules = build_rules()?;
    let ignores = IgnoreMatcher::from_file(&config.ignore_file)?;
    let mut findings = Vec::new();
    let mut scan_summary = ScanSummary::default();
    let mut syntax_parser = Parser::new();

    {
        let mut scan_state = ScanState {
            root: &config.workspace,
            rules: &rules,
            ignores: &ignores,
            ignore_file: &config.ignore_file,
            syntax_parser: &mut syntax_parser,
            findings: &mut findings,
            scan_summary: &mut scan_summary,
        };
        scan_state.scan_directory(&config.workspace);
    }

    let report = Report::new(
        repository_identity(&config.workspace),
        config.workspace.display().to_string(),
        config.severity_threshold,
        findings,
        scan_summary,
    );
    write_report(&config.output, &report)?;
    write_sarif(&config.sarif_output, &report)?;

    let blocking = report
        .findings
        .iter()
        .filter(|finding| finding.severity.rank() >= config.severity_threshold.rank())
        .count();
    println!(
        "sec-guard-core: scanned {} file(s), found {} issue(s), {} at or above {}",
        report.scan_summary.scanned_files,
        report.summary.total_findings,
        blocking,
        config.severity_threshold.as_str()
    );
    println!(
        "sec-guard-core: report written to {}",
        config.output.display()
    );
    println!(
        "sec-guard-core: SARIF written to {}",
        config.sarif_output.display()
    );

    if !report.scan_complete {
        eprintln!(
            "sec-guard-core: scan incomplete; oversized, non-UTF-8, or unreadable files were recorded in the report"
        );
        return Ok(2);
    }

    Ok(0)
}

impl Config {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        let mut workspace = PathBuf::from(".");
        let mut output = PathBuf::from(".sec-guard/report.json");
        let mut sarif_output = PathBuf::from(".sec-guard/report.sarif");
        let mut severity_threshold = Severity::High;
        let mut ignore_file = None;
        let mut arguments = env::args().skip(1);

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--workspace" => {
                    workspace = PathBuf::from(
                        arguments
                            .next()
                            .ok_or("--workspace requires a directory path")?,
                    );
                }
                "--output" => {
                    output = PathBuf::from(
                        arguments
                            .next()
                            .ok_or("--output requires a JSON file path")?,
                    );
                }
                "--sarif-output" => {
                    sarif_output = PathBuf::from(
                        arguments
                            .next()
                            .ok_or("--sarif-output requires a SARIF file path")?,
                    );
                }
                "--ignore-file" => {
                    ignore_file = Some(PathBuf::from(
                        arguments.next().ok_or("--ignore-file requires a path")?,
                    ));
                }
                "--severity-threshold" => {
                    severity_threshold = Severity::parse(
                        &arguments
                            .next()
                            .ok_or("--severity-threshold requires a value")?,
                    )?;
                }
                unknown => return Err(format!("unknown argument '{unknown}'").into()),
            }
        }

        if !workspace.is_dir() {
            return Err(format!("workspace is not a directory: {}", workspace.display()).into());
        }

        let workspace = fs::canonicalize(workspace)?;
        let ignore_file = ignore_file
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join(".sec-guardignore"));

        Ok(Self {
            workspace,
            output,
            sarif_output,
            severity_threshold,
            ignore_file,
        })
    }
}

impl IgnoreMatcher {
    fn from_file(path: &Path) -> Result<Self, Box<dyn Error>> {
        if !path.exists() {
            return Ok(Self {
                patterns: Vec::new(),
            });
        }

        let contents = fs::read_to_string(path)?;
        let mut patterns = Vec::new();
        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            patterns.push(compile_ignore_pattern(line)?);
        }
        Ok(Self { patterns })
    }

    fn matches(&self, relative_path: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.is_match(relative_path))
    }
}

fn compile_ignore_pattern(raw_pattern: &str) -> Result<Regex, regex::Error> {
    let mut pattern = raw_pattern.trim().replace('\\', "/");
    let directory_pattern = pattern.ends_with('/');
    pattern = pattern.trim_matches('/').to_string();
    let has_slash = pattern.contains('/');
    let mut expression = String::from("^");
    if !has_slash {
        expression.push_str("(?:.*/)?");
    }

    for character in pattern.chars() {
        match character {
            '*' if has_slash => expression.push_str(".*"),
            '*' => expression.push_str("[^/]*"),
            '?' => expression.push_str("[^/]"),
            _ => expression.push_str(&regex::escape(&character.to_string())),
        }
    }

    if directory_pattern {
        expression.push_str("(?:/.*)?");
    }
    expression.push('$');
    Regex::new(&expression)
}

fn print_usage() {
    println!(
        "Usage: sec-guard-core [--workspace PATH] [--output PATH] [--sarif-output PATH] [--ignore-file PATH] [--severity-threshold LEVEL]"
    );
}

fn build_rules() -> Result<Vec<Rule>, regex::Error> {
    Ok(vec![
        Rule {
            id: "SEC001",
            severity: Severity::High,
            title: "Potential hard-coded secret",
            description: "A credential-shaped value appears to be assigned directly in source code.",
            remediation: "Move the value to a secret manager or environment variable and rotate it if it is real.",
            pattern: Regex::new(
                r#"(?i)(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*["'][^"']{8,}["']"#,
            )?,
            redact_evidence: true,
        },
        Rule {
            id: "SEC002",
            severity: Severity::Critical,
            title: "Possible AWS access key",
            description: "The file contains a value shaped like an AWS access key identifier.",
            remediation: "Revoke and rotate the credential, then load it from a managed secret store.",
            pattern: Regex::new(r"\bAKIA[0-9A-Z]{16}\b")?,
            redact_evidence: true,
        },
        Rule {
            id: "SEC003",
            severity: Severity::Critical,
            title: "Private key material detected",
            description: "The file contains a PEM private-key header.",
            remediation: "Remove the key from version control, revoke it, and use a secret manager.",
            pattern: Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")?,
            redact_evidence: true,
        },
        Rule {
            id: "SEC004",
            severity: Severity::High,
            title: "Possible GitHub token",
            description: "The file contains a value shaped like a GitHub personal access token.",
            remediation: "Revoke the token and use the workflow token or an encrypted repository secret.",
            pattern: Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")?,
            redact_evidence: true,
        },
        Rule {
            id: "SEC005",
            severity: Severity::Medium,
            title: "Dynamic evaluation call",
            description: "A direct eval call can execute untrusted input in some runtimes.",
            remediation: "Prefer a safe parser or an allow-listed interpreter with validated input.",
            pattern: Regex::new(r"(?i)\beval\s*\(")?,
            redact_evidence: true,
        },
    ])
}

impl<'a> ScanState<'a> {
    fn scan_directory(&mut self, current: &Path) {
        let entries = match fs::read_dir(current) {
            Ok(entries) => entries,
            Err(error) => {
                self.scan_summary.read_errors.push(ScanError {
                    path: relative_path(self.root, current),
                    error: error.to_string(),
                });
                return;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.scan_summary.read_errors.push(ScanError {
                        path: relative_path(self.root, current),
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            let relative = relative_path(self.root, &path);
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    self.scan_summary.read_errors.push(ScanError {
                        path: relative,
                        error: error.to_string(),
                    });
                    continue;
                }
            };

            if path == self.ignore_file {
                self.scan_summary.ignored_files += 1;
                continue;
            }

            if file_type.is_dir() {
                let default_ignored = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| SKIP_DIRS.contains(&name));
                if default_ignored || self.ignores.matches(&relative) {
                    self.scan_summary.ignored_directories += 1;
                    continue;
                }
                self.scan_directory(&path);
            } else if file_type.is_file() {
                if self.ignores.matches(&relative) {
                    self.scan_summary.ignored_files += 1;
                    continue;
                }
                if !is_candidate_file(&path) {
                    self.scan_summary.skipped_non_text_files += 1;
                    continue;
                }
                if let Err(error) = self.scan_file(&path) {
                    self.scan_summary.read_errors.push(ScanError {
                        path: relative,
                        error: error.to_string(),
                    });
                }
            }
        }
    }

    fn scan_file(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        let relative_path = relative_path(self.root, path);
        if fs::metadata(path)?.len() > MAX_FILE_BYTES {
            self.scan_summary.oversized_files.push(relative_path);
            return Ok(());
        }

        let bytes = fs::read(path)?;
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => {
                self.scan_summary.non_utf8_files.push(relative_path);
                return Ok(());
            }
        };
        self.scan_summary.scanned_files += 1;
        check_syntax(
            path,
            &content,
            self.syntax_parser,
            self.scan_summary,
            &relative_path,
        )?;

        for rule in self.rules {
            for (line_index, line) in content.lines().enumerate() {
                if rule.pattern.is_match(line) {
                    self.findings.push(Finding {
                        id: rule.id.to_string(),
                        severity: rule.severity,
                        title: rule.title.to_string(),
                        description: rule.description.to_string(),
                        file: relative_path.clone(),
                        line: Some(line_index + 1),
                        evidence: evidence_for(rule, line),
                        remediation: rule.remediation.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_candidate_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| TEXT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()))
        .unwrap_or(true)
}

fn check_syntax(
    path: &Path,
    content: &str,
    syntax_parser: &mut Parser,
    scan_summary: &mut ScanSummary,
    relative_path: &str,
) -> Result<(), Box<dyn Error>> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase());
    let language = match extension.as_deref() {
        Some("py") => Some(tree_sitter_python::LANGUAGE.into()),
        Some("rs") => Some(tree_sitter_rust::LANGUAGE.into()),
        _ => None,
    };

    if let Some(language) = language {
        syntax_parser.set_language(&language)?;
        let tree = syntax_parser
            .parse(content, None)
            .ok_or("tree-sitter returned no syntax tree")?;
        if tree.root_node().has_error() {
            scan_summary
                .syntax_error_files
                .push(relative_path.to_string());
        }
    }
    Ok(())
}

fn evidence_for(rule: &Rule, line: &str) -> String {
    if rule.redact_evidence {
        return "<redacted: credential-shaped value>".to_string();
    }

    let trimmed = line.trim();
    let mut evidence = trimmed.chars().take(200).collect::<String>();
    if trimmed.chars().count() > 200 {
        evidence.push('…');
    }
    evidence
}

fn repository_identity(workspace: &Path) -> String {
    if let Ok(repository) = Repository::discover(workspace) {
        if let Ok(remote) = repository.find_remote("origin") {
            if let Ok(url) = remote.url() {
                return sanitize_repository_url(url.trim_end_matches(".git"));
            }
        }
    }

    if let Ok(repository) = env::var("GITHUB_REPOSITORY") {
        return format!("https://github.com/{repository}");
    }

    "checked-out workspace".to_string()
}

fn sanitize_repository_url(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = value[authority_start..]
        .find('/')
        .map(|offset| authority_start + offset)
        .unwrap_or(value.len());
    let authority = &value[authority_start..authority_end];
    if let Some(user_info_end) = authority.rfind('@') {
        return format!(
            "{}{}{}",
            &value[..authority_start],
            &authority[user_info_end + 1..],
            &value[authority_end..]
        );
    }
    value.to_string()
}

fn write_report(output: &Path, report: &Report) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(output)?;
    serde_json::to_writer_pretty(file, report)?;
    Ok(())
}

fn write_sarif(output: &Path, report: &Report) -> Result<(), Box<dyn Error>> {
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        rules.entry(finding.id.clone()).or_insert_with(|| {
            json!({
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
                "helpUri": "https://github.com/dabdul-wahab1988/sec-guard-action#security-rules"
            })
        });
    }

    let results = report
        .findings
        .iter()
        .map(|finding| {
            let region = finding.line.map(|line| json!({"startLine": line}));
            let location = if let Some(region) = region {
                json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": region
                    }
                })
            } else {
                json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file,
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                })
            };
            json!({
                "ruleId": finding.id,
                "level": sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [location]
            })
        })
        .collect::<Vec<_>>();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sec-guard-core",
                    "version": report.schema_version,
                    "informationUri": "https://github.com/dabdul-wahab1988/sec-guard-action",
                    "rules": rules.values().cloned().collect::<Vec<_>>()
                }
            },
            "results": results
        }]
    });

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(output)?;
    serde_json::to_writer_pretty(file, &sarif)?;
    Ok(())
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "note",
        Severity::Low | Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::{build_rules, compile_ignore_pattern, evidence_for, is_candidate_file};
    use std::path::Path;

    #[test]
    fn candidate_file_detection_accepts_source_and_extensionless_files() {
        assert!(is_candidate_file(Path::new("src/main.rs")));
        assert!(is_candidate_file(Path::new("Dockerfile")));
        assert!(!is_candidate_file(Path::new("image.png")));
    }

    #[test]
    fn secret_evidence_is_redacted() {
        let rules = build_rules().expect("rules compile");
        let source_line = format!("{} = 'do-not-print-this-value'", "api_key");
        assert_eq!(
            evidence_for(&rules[0], &source_line),
            "<redacted: credential-shaped value>"
        );
        assert_eq!(
            evidence_for(&rules[4], "eval(password='co-located-secret')"),
            "<redacted: credential-shaped value>"
        );
    }

    #[test]
    fn ignore_patterns_match_directories_and_basename_globs() {
        assert!(compile_ignore_pattern("secrets/")
            .expect("directory pattern compiles")
            .is_match("secrets/credentials.env"));
        assert!(compile_ignore_pattern("*.pem")
            .expect("basename pattern compiles")
            .is_match("certificates/server.pem"));
        assert!(!compile_ignore_pattern("*.pem")
            .expect("basename pattern compiles")
            .is_match("certificates/server.txt"));
    }

    #[test]
    fn repository_url_user_info_is_removed() {
        assert_eq!(
            super::sanitize_repository_url("https://token:password@github.com/org/repo"),
            "https://github.com/org/repo"
        );
    }
}
