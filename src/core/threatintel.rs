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

/// Matches package sources, URLs, domains, maintainers, and hashes against
/// the local threat indicator database.
pub struct ThreatIntelEngine<'a> {
    db: &'a Database,
}

impl<'a> ThreatIntelEngine<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Checks a set of candidate indicators (domains, URLs, maintainer names, hashes)
    /// against stored IOC records.
    pub fn match_candidates(&self, candidates: &[String]) -> Vec<IocMatch> {
        let mut matches = Vec::new();
        for val in candidates {
            if let Ok(Some(ioc)) = self.db.lookup_indicator(val) {
                matches.push(IocMatch {
                    indicator: ioc.indicator,
                    kind: ioc.kind,
                    severity: ioc.severity,
                    confidence: ioc.confidence,
                    source: ioc.source,
                });
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
    fn returns_zero_when_no_indicators_match() {
        let db = Database::open_in_memory().unwrap();
        let engine = ThreatIntelEngine::new(&db);
        let matches = engine.match_candidates(&["safe-host.com".into()]);
        assert!(matches.is_empty());
        assert_eq!(engine.calculate_score(&matches), 0);
    }
}
