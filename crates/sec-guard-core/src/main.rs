mod models;

use git2::Repository;
use models::{Finding, Report, Severity};
use regex::Regex;
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
    severity_threshold: Severity,
}

fn main() {
    if let Err(error) = try_main() {
        eprintln!("sec-guard-core: {error}");
        std::process::exit(2);
    }
}

fn try_main() -> Result<(), Box<dyn Error>> {
    if env::args().any(|argument| argument == "--help" || argument == "-h") {
        print_usage();
        return Ok(());
    }

    let config = Config::from_args()?;
    let rules = build_rules()?;
    let mut findings = Vec::new();

    // The parser is intentionally created here so language-specific tree-sitter
    // rules can be added without changing the CLI contract in a future release.
    let _syntax_parser = Parser::new();
    scan_directory(&config.workspace, &config.workspace, &rules, &mut findings)?;

    let report = Report::new(
        repository_identity(&config.workspace),
        config.workspace.display().to_string(),
        config.severity_threshold,
        findings,
    );
    write_report(&config.output, &report)?;

    let blocking = report
        .findings
        .iter()
        .filter(|finding| finding.severity.rank() >= config.severity_threshold.rank())
        .count();
    println!(
        "sec-guard-core: scanned {} finding(s), {} at or above {}",
        report.summary.total_findings,
        blocking,
        config.severity_threshold.as_str()
    );
    println!(
        "sec-guard-core: report written to {}",
        config.output.display()
    );
    Ok(())
}

impl Config {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        let mut workspace = PathBuf::from(".");
        let mut output = PathBuf::from(".sec-guard/report.json");
        let mut severity_threshold = Severity::High;
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

        Ok(Self {
            workspace: fs::canonicalize(workspace)?,
            output,
            severity_threshold,
        })
    }
}

fn print_usage() {
    println!(
        "Usage: sec-guard-core [--workspace PATH] [--output PATH] [--severity-threshold LEVEL]"
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
            redact_evidence: false,
        },
    ])
}

fn scan_directory(
    root: &Path,
    current: &Path,
    rules: &[Rule],
    findings: &mut Vec<Finding>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| SKIP_DIRS.contains(&name))
            {
                continue;
            }
            scan_directory(root, &path, rules, findings)?;
        } else if file_type.is_file() && is_candidate_file(&path) {
            scan_file(root, &path, rules, findings)?;
        }
    }
    Ok(())
}

fn is_candidate_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| TEXT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()))
        .unwrap_or(true)
}

fn scan_file(
    root: &Path,
    path: &Path,
    rules: &[Rule],
    findings: &mut Vec<Finding>,
) -> Result<(), Box<dyn Error>> {
    if fs::metadata(path)?.len() > MAX_FILE_BYTES {
        return Ok(());
    }

    let bytes = fs::read(path)?;
    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(_) => return Ok(()),
    };
    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    for rule in rules {
        for (line_index, line) in content.lines().enumerate() {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
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
                return url.trim_end_matches(".git").to_string();
            }
        }
    }

    if let Ok(repository) = env::var("GITHUB_REPOSITORY") {
        return format!("https://github.com/{repository}");
    }

    workspace.display().to_string()
}

fn write_report(output: &Path, report: &Report) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(output)?;
    serde_json::to_writer_pretty(file, report)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_rules, evidence_for, is_candidate_file};
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
    }
}
