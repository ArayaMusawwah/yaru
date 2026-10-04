use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// `~/.config/yaru/config.toml` — user-overridable defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YaruConfig {
    #[serde(default)]
    pub whitelisted_rules: Vec<String>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub ioc_feed: IocFeedConfig,
    #[serde(default)]
    pub ai: AiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub on_engine_failure: crate::core::types::FailureMode,
    #[serde(default)]
    pub on_warn: WarnAction,
    #[serde(default = "default_allow_below")]
    pub allow_below: u32,
    #[serde(default = "default_warn_below")]
    pub warn_below: u32,
    #[serde(default = "default_quarantine_below")]
    pub quarantine_below: u32,
}

fn default_allow_below() -> u32 {
    30
}
fn default_warn_below() -> u32 {
    60
}
fn default_quarantine_below() -> u32 {
    80
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            on_engine_failure: crate::core::types::FailureMode::Warn,
            on_warn: WarnAction::Block,
            allow_below: 30,
            warn_below: 60,
            quarantine_below: 80,
        }
    }
}

/// Response to a WARN verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WarnAction {
    Continue,
    #[default]
    Block,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub network_mode: NetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
pub enum NetworkMode {
    #[default]
    Strict,
    SourceAllowlist,
    Audit,
}

/// Community IOC feed configuration. Disabled by default; the URL is
/// user-configured only — no hardcoded third-party endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeedConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
}

impl Default for IocFeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            refresh_hours: default_refresh_hours(),
        }
    }
}

fn default_refresh_hours() -> u64 {
    24
}

/// AI-assisted triage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default = "default_ai_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ai_provider")]
    pub provider: String,
    #[serde(default = "default_ai_base_url")]
    pub base_url: String,
    #[serde(default = "default_ai_model")]
    pub model: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_ai_language")]
    pub language: String,
    #[serde(default = "default_ai_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_ai_cache_ttl_hours")]
    pub cache_ttl_hours: u64,
}

fn default_ai_enabled() -> bool {
    true
}
fn default_ai_provider() -> String {
    "openai".to_string()
}
fn default_ai_base_url() -> String {
    "http://localhost:20128/v1".to_string()
}
fn default_ai_model() -> String {
    "1.beeg-brain".to_string()
}
fn default_ai_language() -> String {
    "id".to_string()
}
fn default_ai_timeout_secs() -> u64 {
    30
}
fn default_ai_cache_ttl_hours() -> u64 {
    72
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: default_ai_enabled(),
            provider: default_ai_provider(),
            base_url: default_ai_base_url(),
            model: default_ai_model(),
            api_key: None,
            language: default_ai_language(),
            timeout_secs: default_ai_timeout_secs(),
            cache_ttl_hours: default_ai_cache_ttl_hours(),
        }
    }
}

impl AiConfig {
    pub fn resolved_api_key(&self) -> Option<String> {
        self.api_key
            .clone()
            .or_else(|| std::env::var("YARU_AI_API_KEY").ok())
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config file at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Returns the configuration. Missing file yields Default (first run).
/// A file that exists but fails to parse returns an Error: silent fallback
/// would silently drop security settings on a single typo.
pub fn load() -> Result<YaruConfig, ConfigError> {
    if let Ok(env_dir) = std::env::var("YARU_CONFIG_DIR") {
        let p = PathBuf::from(env_dir).join("config.toml");
        if p.exists() {
            return parse(&p);
        }
        return Ok(YaruConfig::default());
    }

    match dirs::config_dir().map(|d| d.join("yaru").join("config.toml")) {
        Some(p) if p.exists() => parse(&p),
        _ => Ok(YaruConfig::default()),
    }
}

fn parse(path: &Path) -> Result<YaruConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn missing_file_gives_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("YARU_CONFIG_DIR", tmp.path()) };
        let cfg = load().unwrap();
        unsafe { std::env::remove_var("YARU_CONFIG_DIR") };
        assert_eq!(cfg.policy.on_warn, WarnAction::Block);
        assert_eq!(cfg.sandbox.network_mode, NetworkMode::Strict);
    }

    #[test]
    fn malformed_config_fails_loud_instead_of_silent_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("config.toml"), b"this is [ not valid toml").unwrap();
        unsafe { std::env::set_var("YARU_CONFIG_DIR", tmp.path()) };
        let res = load();
        unsafe { std::env::remove_var("YARU_CONFIG_DIR") };
        assert!(res.is_err(), "malformed config must return Err");
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("invalid config file"));
    }

    #[test]
    fn feed_config_is_disabled_by_default() {
        let cfg = YaruConfig::default();
        assert!(!cfg.ioc_feed.enabled);
        assert!(cfg.ioc_feed.url.is_empty());
        assert_eq!(cfg.ioc_feed.refresh_hours, 24);
    }

    #[test]
    fn feed_config_parses_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            br#"[ioc_feed]
enabled = true
url = "https://example.com/iocs.json"
refresh_hours = 12
"#,
        )
        .unwrap();
        let cfg = parse(&path).unwrap();
        assert!(cfg.ioc_feed.enabled);
        assert_eq!(cfg.ioc_feed.url, "https://example.com/iocs.json");
        assert_eq!(cfg.ioc_feed.refresh_hours, 12);
    }

    #[test]
    fn ai_config_defaults() {
        let cfg = AiConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.provider, "openai");
        assert_eq!(cfg.base_url, "http://localhost:20128/v1");
        assert_eq!(cfg.model, "1.beeg-brain");
        assert_eq!(cfg.language, "id");
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.cache_ttl_hours, 72);
        assert_eq!(cfg.api_key, None);
    }

    #[test]
    fn ai_config_parses_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            br#"[ai]
enabled = false
base_url = "http://127.0.0.1:11434/v1"
model = "deepseek-r1"
language = "en"
cache_ttl_hours = 24
"#,
        )
        .unwrap();
        let cfg = parse(&path).unwrap();
        assert!(!cfg.ai.enabled);
        assert_eq!(cfg.ai.base_url, "http://127.0.0.1:11434/v1");
        assert_eq!(cfg.ai.model, "deepseek-r1");
        assert_eq!(cfg.ai.language, "en");
        assert_eq!(cfg.ai.cache_ttl_hours, 24);
    }

    #[test]
    fn ai_config_resolves_env_api_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = AiConfig {
            api_key: Some("cfg-key".into()),
            ..Default::default()
        };
        assert_eq!(cfg.resolved_api_key(), Some("cfg-key".into()));

        cfg.api_key = None;
        unsafe { std::env::set_var("YARU_AI_API_KEY", "env-key") };
        assert_eq!(cfg.resolved_api_key(), Some("env-key".into()));
        unsafe { std::env::remove_var("YARU_AI_API_KEY") };
    }
}
