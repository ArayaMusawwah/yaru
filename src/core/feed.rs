use crate::storage::{Database, FeedState, StorageError, ThreatIndicator};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for an IOC feed source.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedConfig {
    pub enabled: bool,
    pub url: String,
    pub refresh_hours: u64,
}

/// Result of a feed synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSyncResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
    pub last_success: i64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Fetch indicators from raw feed text (JSON or YAML).
///
/// Returns the number of indicators imported. Content type is determined
/// by the `content_type` parameter (e.g. `application/json`).
pub fn import_from_text(db: &Database, text: &str, content_type: &str) -> Result<usize, FeedError> {
    if text.trim().is_empty() {
        return Ok(0);
    }
    let indicators: Vec<ThreatIndicator> = if content_type.contains("json") {
        serde_json::from_str(text).map_err(|e| FeedError::Parse(e.to_string()))?
    } else if content_type.contains("yaml") || content_type.contains("yml") {
        serde_yaml::from_str(text).map_err(|e| FeedError::Parse(e.to_string()))?
    } else {
        return Err(FeedError::InvalidContentType(content_type.to_string()));
    };

    for ind in &indicators {
        if ind.indicator.trim().is_empty()
            || !(0.0..=1.0).contains(&ind.confidence)
            || ind.kind.trim().is_empty()
        {
            return Err(FeedError::InvalidIndicator);
        }
    }

    let count = indicators.len();
    for ind in indicators {
        db.store_indicator(&ind).map_err(FeedError::Storage)?;
    }
    Ok(count)
}

/// Synchronize a feed into the local threat-indicator database.
///
/// Uses conditional GET with ETag / If-Modified-Since so repeated calls
/// with unchanged feed content are no-ops (HTTP 304).
pub async fn sync_feed(
    client: &reqwest::Client,
    db: &Database,
    config: &FeedConfig,
) -> Result<FeedSyncResult, FeedError> {
    if !config.enabled {
        return Err(FeedError::Disabled);
    }
    if config.url.trim().is_empty() {
        return Err(FeedError::MissingUrl);
    }

    let state = db.get_feed_state(&config.url)?;

    let mut req = client.get(&config.url).timeout(Duration::from_secs(30));
    if let Some(etag) = state.as_ref().and_then(|s| s.etag.as_deref()) {
        req = req.header("If-None-Match", etag);
    }
    if let Some(lm) = state.as_ref().and_then(|s| s.last_modified.as_deref()) {
        req = req.header("If-Modified-Since", lm);
    }

    let resp = req.send().await.map_err(FeedError::Http)?;

    // 304 Not Modified — nothing to do
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        let empty = FeedState {
            url: config.url.clone(),
            etag: None,
            last_modified: None,
            last_success: 0,
        };
        let prev = state.as_ref().unwrap_or(&empty);
        return Ok(FeedSyncResult {
            added: 0,
            updated: 0,
            skipped: 0,
            last_success: prev.last_success,
            etag: prev.etag.clone(),
            last_modified: prev.last_modified.clone(),
        });
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !content_type.contains("json")
        && !content_type.contains("yaml")
        && !content_type.contains("yml")
    {
        return Err(FeedError::InvalidContentType(content_type));
    }

    // Capture headers before body is consumed
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let last_modified = resp
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp.text().await.map_err(FeedError::Http)?;
    let count = import_from_text(db, &body, &content_type)?;

    let now = chrono::Utc::now().timestamp();
    db.save_feed_state(&FeedState {
        url: config.url.clone(),
        etag: etag.clone(),
        last_modified: last_modified.clone(),
        last_success: now,
    })?;

    Ok(FeedSyncResult {
        added: count,
        updated: 0,
        skipped: 0,
        last_success: now,
        etag,
        last_modified,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("feed disabled in config")]
    Disabled,
    #[error("feed URL not configured")]
    MissingUrl,
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid content type: {0}, expected JSON or YAML")]
    InvalidContentType(String),
    #[error("invalid indicator: missing indicator, kind, or confidence out of range")]
    InvalidIndicator,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;

    #[test]
    fn disabled_feed_returns_error() {
        let cfg = FeedConfig {
            enabled: false,
            url: "https://example.com/feed.json".into(),
            refresh_hours: 24,
        };
        let db = Database::open_in_memory().unwrap();
        let client = reqwest::Client::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(sync_feed(&client, &db, &cfg));
        assert!(matches!(res, Err(FeedError::Disabled)));
    }

    #[test]
    fn missing_url_returns_error() {
        let cfg = FeedConfig {
            enabled: true,
            url: "".into(),
            refresh_hours: 24,
        };
        let db = Database::open_in_memory().unwrap();
        let client = reqwest::Client::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(sync_feed(&client, &db, &cfg));
        assert!(matches!(res, Err(FeedError::MissingUrl)));
    }

    #[test]
    fn import_json_indicators() {
        let db = Database::open_in_memory().unwrap();
        let text = r#"[{"indicator":"evil.example","kind":"domain","severity":"Critical","confidence":0.95,"source":"feed","first_seen":1,"last_seen":1,"status":"active"}]"#;
        let count = import_from_text(&db, text, "application/json").unwrap();
        assert_eq!(count, 1);
        assert!(db.lookup_indicator("evil.example").unwrap().is_some());
    }

    #[test]
    fn import_yaml_indicators() {
        let db = Database::open_in_memory().unwrap();
        let text = r#"- indicator: evil.example
  kind: domain
  severity: Critical
  confidence: 0.95
  source: feed
  first_seen: 1
  last_seen: 1
  status: active"#;
        let count = import_from_text(&db, text, "application/x-yaml").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn invalid_content_type_returns_error() {
        let db = Database::open_in_memory().unwrap();
        let res = import_from_text(&db, "not json", "text/plain");
        assert!(matches!(res, Err(FeedError::InvalidContentType(_))));
    }

    #[test]
    fn http_304_returns_no_op_without_downloading() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/iocs.json", addr);

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 304 Not Modified\r\n\r\n");
            }
        });

        thread::sleep(Duration::from_millis(50));

        let db = Database::open_in_memory().unwrap();
        // Save state with ETag to trigger If-None-Match
        db.save_feed_state(&crate::storage::FeedState {
            url: url.clone(),
            etag: Some("\"v1\"".into()),
            last_modified: None,
            last_success: 0,
        })
        .unwrap();

        let client = reqwest::Client::new();
        let cfg = FeedConfig {
            enabled: true,
            url,
            refresh_hours: 24,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(sync_feed(&client, &db, &cfg));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.added, 0);
        assert_eq!(result.skipped, 0);
    }
}
