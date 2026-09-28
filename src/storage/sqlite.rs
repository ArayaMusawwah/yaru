use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::types::{MaintainerChange, PackageSnapshot, Verdict};
use crate::storage::models::{CachedScan, DecisionRecord, FeedState, ThreatIndicator};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Database {
    conn: Connection,
}

const SNAPSHOT_COLUMNS: &str = "version, maintainer, pkgbuild_hash, source_urls, depends, \
                                makedepends, checkdepends, timestamp";

impl Database {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.configure()?;
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.configure()?;
        db.migrate()?;
        Ok(db)
    }

    fn configure(&self) -> Result<(), StorageError> {
        self.conn
            .query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        self.conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS package_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                version TEXT,
                maintainer TEXT,
                pkgbuild_hash TEXT NOT NULL,
                source_urls TEXT NOT NULL,
                depends TEXT NOT NULL,
                makedepends TEXT NOT NULL,
                checkdepends TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_snapshots
                ON package_snapshots(package_name, timestamp);
            CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                source TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                status TEXT NOT NULL,
                UNIQUE(indicator, kind)
            );
            CREATE TABLE IF NOT EXISTS maintainer_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                previous TEXT,
                current TEXT,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feed_state (
                url TEXT PRIMARY KEY,
                etag TEXT,
                last_modified TEXT,
                last_success INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS scan_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                breakdown TEXT NOT NULL,
                findings TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT NOT NULL,
                snapshot TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_cache
                ON scan_cache(package_name, fingerprint, timestamp);
            CREATE TABLE IF NOT EXISTS scan_cache_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_cache_hits
                ON scan_cache_hits(timestamp);",
        )?;
        Ok(())
    }

    pub fn save_snapshot(&self, snap: &PackageSnapshot) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO package_snapshots (
                package_name, version, maintainer, pkgbuild_hash, source_urls,
                depends, makedepends, checkdepends, timestamp
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                snap.package_name,
                snap.version,
                snap.maintainer,
                snap.pkgbuild_hash,
                encode(&snap.source_urls)?,
                encode(&snap.depends)?,
                encode(&snap.makedepends)?,
                encode(&snap.checkdepends)?,
                snap.timestamp,
            ],
        )?;
        Ok(())
    }

    pub fn latest_snapshot(&self, package: &str) -> Result<Option<PackageSnapshot>, StorageError> {
        let sql = format!(
            "SELECT {SNAPSHOT_COLUMNS} FROM package_snapshots
             WHERE package_name = ?1 ORDER BY timestamp DESC, id DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![package], |row| snapshot_row(row, package))
            .optional()
            .map_err(StorageError::from)
    }

    pub fn list_snapshots(&self, package: &str) -> Result<Vec<PackageSnapshot>, StorageError> {
        let sql = format!(
            "SELECT {SNAPSHOT_COLUMNS} FROM package_snapshots
             WHERE package_name = ?1 ORDER BY timestamp ASC, id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![package], |row| snapshot_row(row, package))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn total_snapshots(&self) -> Result<usize, StorageError> {
        let count: usize =
            self.conn
                .query_row("SELECT COUNT(*) FROM package_snapshots", [], |row| {
                    row.get(0)
                })?;
        Ok(count)
    }

    pub fn record_decision(&self, rec: &DecisionRecord) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO policy_decisions (package_name, score, verdict, reasons, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                rec.package,
                rec.score,
                encode(&rec.verdict)?,
                encode(&rec.reasons)?,
                rec.timestamp,
            ],
        )?;
        Ok(())
    }

    pub fn list_decisions(&self, package: &str) -> Result<Vec<DecisionRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT package_name, score, verdict, reasons, timestamp FROM policy_decisions
             WHERE package_name = ?1 ORDER BY timestamp ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![package], |row| {
            Ok(DecisionRecord {
                package: row.get(0)?,
                score: row.get(1)?,
                verdict: decode(row, 2)?,
                reasons: decode(row, 3)?,
                timestamp: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn save_scan_cache(&self, cache: &CachedScan) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO scan_cache (
                package_name, fingerprint, breakdown, findings, verdict, reasons, snapshot, timestamp
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                cache.package,
                cache.fingerprint,
                encode(&cache.breakdown)?,
                encode(&cache.findings)?,
                encode(&cache.verdict)?,
                encode(&cache.reasons)?,
                encode(&cache.snapshot)?,
                cache.timestamp,
            ],
        )?;
        Ok(())
    }

    pub fn get_valid_scan_cache(
        &self,
        package: &str,
        fingerprint: &str,
        max_age_seconds: i64,
    ) -> Result<Option<CachedScan>, StorageError> {
        let minimum_timestamp = chrono::Utc::now()
            .timestamp()
            .saturating_sub(max_age_seconds);
        self.conn
            .query_row(
                "SELECT package_name, fingerprint, breakdown, findings, verdict, reasons, snapshot, timestamp
                 FROM scan_cache
                 WHERE package_name = ?1 AND fingerprint = ?2 AND timestamp >= ?3
                 ORDER BY timestamp DESC, id DESC LIMIT 1",
                params![package, fingerprint, minimum_timestamp],
                |row| {
                    Ok(CachedScan {
                        package: row.get(0)?,
                        fingerprint: row.get(1)?,
                        breakdown: decode(row, 2)?,
                        findings: decode(row, 3)?,
                        verdict: decode(row, 4)?,
                        reasons: decode(row, 5)?,
                        snapshot: decode(row, 6)?,
                        timestamp: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn store_indicator(&self, ioc: &ThreatIndicator) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO threat_indicators (
                indicator, kind, severity, confidence, source, first_seen, last_seen, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(indicator, kind) DO UPDATE SET
                severity = excluded.severity,
                confidence = excluded.confidence,
                source = excluded.source,
                last_seen = excluded.last_seen,
                status = excluded.status",
            params![
                ioc.indicator,
                ioc.kind,
                encode(&ioc.severity)?,
                ioc.confidence,
                ioc.source,
                ioc.first_seen,
                ioc.last_seen,
                ioc.status,
            ],
        )?;
        Ok(())
    }

    pub fn lookup_indicator(&self, value: &str) -> Result<Option<ThreatIndicator>, StorageError> {
        self.conn
            .query_row(
                "SELECT indicator, kind, severity, confidence, source, first_seen, last_seen, status
                 FROM threat_indicators WHERE indicator = ?1 ORDER BY last_seen DESC LIMIT 1",
                params![value],
                |row| {
                    Ok(ThreatIndicator {
                        indicator: row.get(0)?,
                        kind: row.get(1)?,
                        severity: decode(row, 2)?,
                        confidence: row.get(3)?,
                        source: row.get(4)?,
                        first_seen: row.get(5)?,
                        last_seen: row.get(6)?,
                        status: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn save_maintainer_change(&self, ch: &MaintainerChange) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO maintainer_changes (package_name, previous, current, kind, severity)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ch.package,
                ch.previous,
                ch.current,
                encode(&ch.kind)?,
                encode(&ch.severity)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_maintainer_changes(
        &self,
        package: &str,
    ) -> Result<Vec<MaintainerChange>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT package_name, previous, current, kind, severity FROM maintainer_changes
             WHERE package_name = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![package], |row| {
            Ok(MaintainerChange {
                package: row.get(0)?,
                previous: row.get(1)?,
                current: row.get(2)?,
                kind: decode(row, 3)?,
                severity: decode(row, 4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn save_feed_state(&self, state: &FeedState) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO feed_state (url, etag, last_modified, last_success)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                state.url,
                state.etag,
                state.last_modified,
                state.last_success
            ],
        )?;
        Ok(())
    }

    pub fn get_feed_state(&self, url: &str) -> Result<Option<FeedState>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT url, etag, last_modified, last_success FROM feed_state WHERE url = ?1",
        )?;
        let state = stmt
            .query_row(params![url], |row| {
                Ok(FeedState {
                    url: row.get(0)?,
                    etag: row.get(1)?,
                    last_modified: row.get(2)?,
                    last_success: row.get(3)?,
                })
            })
            .optional()
            .map_err(StorageError::from)?;
        Ok(state)
    }
}

/// Summary of decisions in a time range.
#[derive(Debug, Clone)]
pub struct DecisionSummary {
    pub total: u32,
    pub allowed: u32,
    pub warned: u32,
    pub quarantined: u32,
    pub blocked: u32,
}

impl Database {
    /// Count decisions grouped by verdict within [from_ts, to_ts].
    pub fn decision_summary(
        &self,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<DecisionSummary, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT verdict, COUNT(*) FROM policy_decisions
             WHERE timestamp BETWEEN ?1 AND ?2
             GROUP BY verdict",
        )?;
        let rows = stmt.query_map(params![from_ts, to_ts], |row| {
            let verdict: String = row.get(0)?;
            let count: u32 = row.get(1)?;
            Ok((verdict, count))
        })?;

        let mut summary = DecisionSummary {
            total: 0,
            allowed: 0,
            warned: 0,
            quarantined: 0,
            blocked: 0,
        };
        for row in rows {
            let (verdict_raw, count) = row?;
            let verdict: Verdict = serde_json::from_str(&verdict_raw).unwrap_or(Verdict::Allow);
            summary.total += count;
            match verdict {
                Verdict::Allow => summary.allowed += count,
                Verdict::Warn => summary.warned += count,
                Verdict::Quarantine => summary.quarantined += count,
                Verdict::Block => summary.blocked += count,
            }
        }
        Ok(summary)
    }

    pub fn record_cache_hit(&self, package: &str) -> Result<(), StorageError> {
        self.record_cache_hit_at(package, chrono::Utc::now().timestamp())
    }

    pub fn record_cache_hit_at(&self, package: &str, timestamp: i64) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO scan_cache_hits (package_name, timestamp) VALUES (?1, ?2)",
            params![package, timestamp],
        )?;
        Ok(())
    }

    pub fn count_cache_hits(&self, from_ts: i64, to_ts: i64) -> Result<u32, StorageError> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM scan_cache_hits WHERE timestamp BETWEEN ?1 AND ?2",
            params![from_ts, to_ts],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

fn snapshot_row(row: &Row<'_>, package: &str) -> rusqlite::Result<PackageSnapshot> {
    Ok(PackageSnapshot {
        package_name: package.to_string(),
        version: row.get(0)?,
        maintainer: row.get(1)?,
        pkgbuild_hash: row.get(2)?,
        source_urls: decode(row, 3)?,
        depends: decode(row, 4)?,
        makedepends: decode(row, 5)?,
        checkdepends: decode(row, 6)?,
        timestamp: row.get(7)?,
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String, StorageError> {
    Ok(serde_json::to_string(value)?)
}

fn decode<T: DeserializeOwned>(row: &Row<'_>, idx: usize) -> rusqlite::Result<T> {
    let raw: String = row.get(idx)?;
    serde_json::from_str(&raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(err))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{MaintainerChangeKind, Severity, Verdict};

    fn snapshot(name: &str, version: &str, timestamp: i64) -> PackageSnapshot {
        PackageSnapshot {
            package_name: name.to_string(),
            version: Some(version.to_string()),
            maintainer: Some("alice".to_string()),
            pkgbuild_hash: "deadbeef".to_string(),
            source_urls: vec!["https://example.com/src.tar.gz".to_string()],
            depends: vec!["glibc".to_string(), "openssl".to_string()],
            makedepends: vec!["gcc".to_string()],
            checkdepends: vec![],
            timestamp,
        }
    }

    #[test]
    fn snapshot_roundtrip_and_latest() {
        let db = Database::open_in_memory().unwrap();
        db.save_snapshot(&snapshot("yay", "1.0.0", 100)).unwrap();
        db.save_snapshot(&snapshot("yay", "1.1.0", 200)).unwrap();

        let latest = db
            .latest_snapshot("yay")
            .unwrap()
            .expect("snapshot must exist");
        assert_eq!(latest.package_name, "yay");
        assert_eq!(latest.version.as_deref(), Some("1.1.0"));
        assert_eq!(latest.timestamp, 200);
        assert_eq!(
            latest.depends,
            vec!["glibc".to_string(), "openssl".to_string()]
        );
        assert_eq!(
            latest.source_urls,
            vec!["https://example.com/src.tar.gz".to_string()]
        );
        assert_eq!(latest.makedepends, vec!["gcc".to_string()]);
        assert!(latest.checkdepends.is_empty());
        assert_eq!(latest.maintainer.as_deref(), Some("alice"));
        assert_eq!(latest.pkgbuild_hash, "deadbeef");
    }

    #[test]
    fn latest_snapshot_returns_none_for_unknown_package() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.latest_snapshot("ghost").unwrap().is_none());
    }

    #[test]
    fn list_snapshots_oldest_first() {
        let db = Database::open_in_memory().unwrap();
        db.save_snapshot(&snapshot("neovim", "0.10", 300)).unwrap();
        db.save_snapshot(&snapshot("neovim", "0.9", 100)).unwrap();
        db.save_snapshot(&snapshot("neovim", "0.9.5", 200)).unwrap();

        let snaps = db.list_snapshots("neovim").unwrap();
        let stamps: Vec<i64> = snaps.iter().map(|s| s.timestamp).collect();
        assert_eq!(stamps, vec![100, 200, 300]);
    }

    #[test]
    fn list_snapshots_is_scoped_to_package() {
        let db = Database::open_in_memory().unwrap();
        db.save_snapshot(&snapshot("neovim", "0.10", 300)).unwrap();
        db.save_snapshot(&snapshot("yay", "12.0", 400)).unwrap();

        let snaps = db.list_snapshots("neovim").unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].package_name, "neovim");
    }

    #[test]
    fn decision_record_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let rec = DecisionRecord {
            package: "curl-evil".to_string(),
            score: 85,
            verdict: Verdict::Block,
            reasons: vec!["curl pipe to sh".to_string(), "new maintainer".to_string()],
            timestamp: 1_700_000_000,
        };
        db.record_decision(&rec).unwrap();

        let got = db.list_decisions("curl-evil").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].package, "curl-evil");
        assert_eq!(got[0].score, 85);
        assert_eq!(got[0].verdict, Verdict::Block);
        assert_eq!(got[0].reasons, rec.reasons);
        assert_eq!(got[0].timestamp, 1_700_000_000);
    }

    #[test]
    fn indicator_upsert_returns_updated_row() {
        let db = Database::open_in_memory().unwrap();
        let first = ThreatIndicator {
            indicator: "evil.example.com".to_string(),
            kind: "domain".to_string(),
            severity: Severity::Medium,
            confidence: 0.5,
            source: "feed-a".to_string(),
            first_seen: 1000,
            last_seen: 1000,
            status: "active".to_string(),
        };
        db.store_indicator(&first).unwrap();

        let updated = ThreatIndicator {
            severity: Severity::Critical,
            confidence: 0.95,
            source: "feed-b".to_string(),
            last_seen: 2000,
            status: "confirmed".to_string(),
            ..first.clone()
        };
        db.store_indicator(&updated).unwrap();

        let got = db
            .lookup_indicator("evil.example.com")
            .unwrap()
            .expect("indicator must exist");
        assert_eq!(got.kind, "domain");
        assert_eq!(got.severity, Severity::Critical);
        assert_eq!(got.confidence, 0.95);
        assert_eq!(got.source, "feed-b");
        assert_eq!(got.last_seen, 2000);
        assert_eq!(got.first_seen, 1000, "first_seen must survive the upsert");
        assert_eq!(got.status, "confirmed");
    }

    #[test]
    fn lookup_indicator_returns_none_for_unknown_value() {
        let db = Database::open_in_memory().unwrap();
        assert!(
            db.lookup_indicator("unknown.example.com")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn feed_state_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let state = crate::storage::FeedState {
            url: "https://example.com/iocs.json".to_string(),
            etag: Some("\"v1\"".to_string()),
            last_modified: Some("Sat, 20 Sep 2026 12:00:00 GMT".to_string()),
            last_success: 1_700_000_000,
        };

        assert!(db.get_feed_state(&state.url).unwrap().is_none());
        db.save_feed_state(&state).unwrap();
        assert_eq!(db.get_feed_state(&state.url).unwrap(), Some(state));
    }

    #[test]
    fn decision_counts_within_time_range() {
        let db = Database::open_in_memory().unwrap();
        for (package, verdict_str, timestamp) in [
            ("alpha", "Allow", 100),
            ("blocked-pkg", "Block", 101),
            ("old-pkg", "Block", 1),
        ] {
            let verdict: Verdict = match verdict_str {
                "Warn" => Verdict::Warn,
                "Quarantine" => Verdict::Quarantine,
                "Block" => Verdict::Block,
                _ => Verdict::Allow,
            };
            db.record_decision(&DecisionRecord {
                package: package.into(),
                score: 0,
                verdict,
                reasons: vec![],
                timestamp,
            })
            .unwrap();
        }

        let summary = db.decision_summary(100, 102).unwrap();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.blocked, 1);
        assert_eq!(summary.allowed, 1);
    }

    #[test]
    fn maintainer_change_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        db.save_maintainer_change(&MaintainerChange {
            package: "yay".to_string(),
            previous: Some("alice".to_string()),
            current: Some("bob".to_string()),
            kind: MaintainerChangeKind::Changed,
            severity: Severity::High,
        })
        .unwrap();
        db.save_maintainer_change(&MaintainerChange {
            package: "yay".to_string(),
            previous: None,
            current: Some("carol".to_string()),
            kind: MaintainerChangeKind::Adopted,
            severity: Severity::Low,
        })
        .unwrap();

        let changes = db.list_maintainer_changes("yay").unwrap();
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].package, "yay");
        assert_eq!(changes[0].previous.as_deref(), Some("alice"));
        assert_eq!(changes[0].current.as_deref(), Some("bob"));
        assert_eq!(changes[0].kind, MaintainerChangeKind::Changed);
        assert_eq!(changes[0].severity, Severity::High);
        assert_eq!(changes[1].previous, None);
        assert_eq!(changes[1].current.as_deref(), Some("carol"));
        assert_eq!(changes[1].kind, MaintainerChangeKind::Adopted);
        assert_eq!(changes[1].severity, Severity::Low);
    }

    #[test]
    fn open_creates_parent_dirs_and_persists() {
        let root = std::env::temp_dir().join(format!("yaru-storage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("nested").join("yaru.db");

        {
            let db = Database::open(&path).unwrap();
            db.save_snapshot(&snapshot("yay", "12.0", 500)).unwrap();
        }

        assert!(path.exists());
        let db = Database::open(&path).unwrap();
        let latest = db
            .latest_snapshot("yay")
            .unwrap()
            .expect("snapshot must persist");
        assert_eq!(latest.version.as_deref(), Some("12.0"));

        drop(db);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn scan_cache_hit_miss_and_expiration() {
        let db = Database::open_in_memory().unwrap();
        let snap = snapshot("ripgrep-all", "0.10.0", 1000);
        let cache_entry = CachedScan {
            package: "ripgrep-all".to_string(),
            fingerprint: "fp-v1-hash123".to_string(),
            breakdown: crate::core::types::ScoreBreakdown::default(),
            findings: Vec::new(),
            verdict: Verdict::Allow,
            reasons: vec!["clean".to_string()],
            snapshot: snap,
            timestamp: chrono::Utc::now().timestamp(),
        };

        db.save_scan_cache(&cache_entry).unwrap();

        // Hit: fingerprint sama & dalam TTL 900s
        let hit = db
            .get_valid_scan_cache("ripgrep-all", "fp-v1-hash123", 900)
            .unwrap();
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().verdict, Verdict::Allow);

        // Miss: fingerprint beda
        let miss_fp = db
            .get_valid_scan_cache("ripgrep-all", "fp-v2-different", 900)
            .unwrap();
        assert!(miss_fp.is_none());

        // Miss: nama paket beda
        let miss_pkg = db
            .get_valid_scan_cache("other-pkg", "fp-v1-hash123", 900)
            .unwrap();
        assert!(miss_pkg.is_none());

        // Expired: entry dengan timestamp 1000 detik lalu (max age 900)
        let mut expired_entry = cache_entry;
        expired_entry.package = "expired-pkg".to_string();
        expired_entry.timestamp = chrono::Utc::now().timestamp() - 1000;
        db.save_scan_cache(&expired_entry).unwrap();

        let expired = db
            .get_valid_scan_cache("expired-pkg", "fp-v1-hash123", 900)
            .unwrap();
        assert!(expired.is_none());
    }

    #[test]
    fn record_and_count_cache_hits() {
        let db = Database::open_in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();
        db.record_cache_hit_at("pkg-a", now - 50).unwrap();
        db.record_cache_hit_at("pkg-b", now - 20).unwrap();
        db.record_cache_hit_at("pkg-old", now - 500).unwrap();

        let count = db.count_cache_hits(now - 100, now).unwrap();
        assert_eq!(count, 2);
    }
}
