use crate::core::types::Severity;
use crate::storage::Database;
use serde::{Deserialize, Serialize};

/// Result of checking indicators against package attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub indicator: String,
    pub kind: String,
    pub severity: Severity,
    pub confidence: f64,
    pub source: String,
}

fn host_of(value: &str) -> Option<String> {
    let without_scheme = value.split_once("://")?.1;
    let authority = without_scheme.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?.trim();
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Matches package sources, URLs, domains, maintainers, and hashes against
/// the local threat indicator database.
pub struct ThreatIntelEngine<'a> {
    db: &'a Database,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("cannot read IOC file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid IOC file {path}: {message}")]
    Parse { path: String, message: String },
    #[error("failed to store IOC: {0}")]
    Storage(#[from] crate::storage::StorageError),
}

/// Imports a JSON or YAML array of threat indicators into SQLite.
pub fn import_indicators(db: &Database, path: &std::path::Path) -> Result<usize, ImportError> {
    let path_display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| ImportError::Io {
        path: path_display.clone(),
        source,
    })?;
    let indicators: Vec<crate::storage::ThreatIndicator> =
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => serde_yaml::from_str(&text).map_err(|e| e.to_string()),
            _ => serde_json::from_str(&text).map_err(|e| e.to_string()),
        }
        .map_err(|message| ImportError::Parse {
            path: path_display,
            message,
        })?;

    for indicator in &indicators {
        if indicator.indicator.trim().is_empty()
            || !(0.0..=1.0).contains(&indicator.confidence)
            || indicator.kind.trim().is_empty()
        {
            return Err(ImportError::Parse {
                path: path.display().to_string(),
                message: "indicator, kind, and confidence 0.0..=1.0 are required".into(),
            });
        }
        db.store_indicator(indicator)?;
    }
    Ok(indicators.len())
}

impl<'a> ThreatIntelEngine<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Checks a set of candidate indicators (domains, URLs, maintainer names, hashes)
    /// against stored IOC records.
    ///
    /// URLs are probed twice: once verbatim and once as their extracted host, so
    /// an IOC of `evil.example` matches `https://evil.example/payload.sh`.
    pub fn match_candidates(&self, candidates: &[String]) -> Vec<IocMatch> {
        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for value in candidates {
            let mut probes = vec![value.clone()];
            if let Some(host) = host_of(value) {
                probes.push(host);
            }

            for probe in probes {
                if !seen.insert(probe.clone()) {
                    continue;
                }
                if let Ok(Some(ioc)) = self.db.lookup_indicator(&probe) {
                    matches.push(IocMatch {
                        indicator: ioc.indicator,
                        kind: ioc.kind,
                        severity: ioc.severity,
                        confidence: ioc.confidence,
                        source: ioc.source,
                    });
                }
            }
        }
        matches
    }

    /// Computes threat risk score from matches (0-100).
    /// Any Critical match with confidence >= 0.8 immediately pegs risk to 100.
    pub fn calculate_score(&self, matches: &[IocMatch]) -> u32 {
        if matches.is_empty() {
            return 0;
        }

        let mut score: u32 = 0;
        for m in matches {
            if m.severity == Severity::Critical && m.confidence >= 0.8 {
                return 100;
            }
            score += (m.severity.weight() as f64 * m.confidence) as u32;
        }
        score.min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ThreatIndicator;

    #[test]
    fn matches_known_malicious_domain() {
        let db = Database::open_in_memory().unwrap();
        db.store_indicator(&ThreatIndicator {
            indicator: "evil-download.org".into(),
            kind: "domain".into(),
            severity: Severity::Critical,
            confidence: 0.95,
            source: "community-feed".into(),
            first_seen: 1000,
            last_seen: 1000,
            status: "active".into(),
        })
        .unwrap();

        let engine = ThreatIntelEngine::new(&db);
        let candidates = vec!["clean.org".into(), "evil-download.org".into()];
        let matches = engine.match_candidates(&candidates);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator, "evil-download.org");
        assert_eq!(engine.calculate_score(&matches), 100);
    }

    #[test]
    fn full_url_matches_domain_level_ioc() {
        let db = Database::open_in_memory().unwrap();
        db.store_indicator(&ThreatIndicator {
            indicator: "bad-host.example".into(),
            kind: "domain".into(),
            severity: Severity::High,
            confidence: 0.9,
            source: "feed".into(),
            first_seen: 1,
            last_seen: 1,
            status: "active".into(),
        })
        .unwrap();

        let engine = ThreatIntelEngine::new(&db);
        let candidates = vec!["https://bad-host.example:8080/path/to/archive.tar.gz?v=1".into()];
        let matches = engine.match_candidates(&candidates);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator, "bad-host.example");
    }

    #[test]
    fn returns_zero_when_no_indicators_match() {
        let db = Database::open_in_memory().unwrap();
        let engine = ThreatIntelEngine::new(&db);
        let matches = engine.match_candidates(&["safe-host.com".into()]);
        assert!(matches.is_empty());
        assert_eq!(engine.calculate_score(&matches), 0);
    }

    #[test]
    fn imports_indicators_from_json_and_yaml() {
        let db = Database::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();

        let json_path = tmp.path().join("i.json");
        std::fs::write(
            &json_path,
            r#"[{"indicator":"bad.com","kind":"domain","severity":"High","confidence":0.9,"source":"t","first_seen":1,"last_seen":1,"status":"a"}]"#,
        )
        .unwrap();
        let count = import_indicators(&db, &json_path).unwrap();
        assert_eq!(count, 1);
        assert!(db.lookup_indicator("bad.com").unwrap().is_some());

        let yaml_path = tmp.path().join("i.yaml");
        std::fs::write(
            &yaml_path,
            "- indicator: malicious.org\n  kind: domain\n  severity: Critical\n  confidence: 0.95\n  source: t\n  first_seen: 1\n  last_seen: 1\n  status: a\n",
        )
        .unwrap();
        let count_yaml = import_indicators(&db, &yaml_path).unwrap();
        assert_eq!(count_yaml, 1);
        assert!(db.lookup_indicator("malicious.org").unwrap().is_some());
    }
}
