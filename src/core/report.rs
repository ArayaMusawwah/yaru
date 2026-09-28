use crate::storage::{Database, StorageError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub from: i64,
    pub to: i64,
    pub scanned: u32,
    pub allowed: u32,
    pub warned: u32,
    pub quarantined: u32,
    pub blocked: u32,
    #[serde(default)]
    pub cache_hits: u32,
}

impl SecurityReport {
    pub fn build(db: &Database, from_ts: i64, to_ts: i64) -> Result<Self, StorageError> {
        let summary = db.decision_summary(from_ts, to_ts)?;
        let cache_hits = db.count_cache_hits(from_ts, to_ts)?;
        Ok(SecurityReport {
            from: from_ts,
            to: to_ts,
            scanned: summary.total,
            allowed: summary.allowed,
            warned: summary.warned,
            quarantined: summary.quarantined,
            blocked: summary.blocked,
            cache_hits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Verdict;
    use crate::storage::{Database, DecisionRecord};
    use chrono::Utc;

    #[test]
    fn empty_report() {
        let db = Database::open_in_memory().unwrap();
        let now = Utc::now().timestamp();
        let report = SecurityReport::build(&db, now - 1000, now).unwrap();
        assert_eq!(report.scanned, 0);
        assert_eq!(report.blocked, 0);
    }

    #[test]
    fn report_counts_verdicts() {
        let db = Database::open_in_memory().unwrap();
        let now = Utc::now().timestamp();

        for (pkg, verdict, ts) in [
            ("alpha", Verdict::Allow, now - 100),
            ("beta", Verdict::Block, now - 50),
            ("gamma", Verdict::Warn, now - 20),
        ] {
            db.record_decision(&DecisionRecord {
                package: pkg.into(),
                score: 0,
                verdict,
                reasons: vec![],
                timestamp: ts,
            })
            .unwrap();
        }

        let report = SecurityReport::build(&db, now - 200, now).unwrap();
        assert_eq!(report.scanned, 3);
        assert_eq!(report.allowed, 1);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.warned, 1);
        assert_eq!(report.cache_hits, 0);

        db.record_cache_hit_at("cached-pkg", now - 10).unwrap();
        let report2 = SecurityReport::build(&db, now - 200, now).unwrap();
        assert_eq!(report2.cache_hits, 1);
    }
}
