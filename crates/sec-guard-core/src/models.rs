use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Severity levels are ordered by `rank` rather than enum declaration order so
/// the comparison remains explicit at call sites.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!(
                "unsupported severity '{value}'; expected info, low, medium, high, or critical"
            )),
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: Option<usize>,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub highest_severity: Option<Severity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    pub schema_version: String,
    pub repository: String,
    pub workspace: String,
    pub generated_at_unix: u64,
    pub severity_threshold: Severity,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
}

impl Report {
    pub fn new(
        repository: String,
        workspace: String,
        severity_threshold: Severity,
        findings: Vec<Finding>,
    ) -> Self {
        let mut by_severity = BTreeMap::new();
        for finding in &findings {
            *by_severity
                .entry(finding.severity.as_str().to_string())
                .or_insert(0) += 1;
        }

        let highest_severity = findings
            .iter()
            .map(|finding| finding.severity)
            .max_by_key(|severity| severity.rank());
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        Self {
            schema_version: "1.0".to_string(),
            repository,
            workspace,
            generated_at_unix,
            severity_threshold,
            findings,
            summary: ReportSummary {
                total_findings: by_severity.values().sum(),
                by_severity,
                highest_severity,
            },
        }
    }
}
