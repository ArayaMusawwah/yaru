use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// `~/.config/yaru/config.toml` — user-overridable defaults.
/// TDM = threshold, whitelist, policy knobs. Kept small on purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaruConfig {
    pub policy: PolicyConfig,
    pub whitelisted_rules: Vec<String>,
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub on_engine_failure: crate::core::types::FailureMode,
    /// Thresholds on the 0-100 composite score.
    pub allow_below: u32,
    pub warn_below: u32,
    pub quarantine_below: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub network_mode: NetworkMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Strict,
    SourceAllowlist,
    Audit,
}

impl Default for YaruConfig {
    fn default() -> Self {
        Self {
            policy: PolicyConfig {
                on_engine_failure: crate::core::types::FailureMode::Warn,
                allow_below: 30,
                warn_below: 60,
                quarantine_below: 80,
            },
            whitelisted_rules: Vec::new(),
            sandbox: SandboxConfig {
                network_mode: NetworkMode::Strict,
            },
        }
    }
}

/// Returns `~/.config/yaru/config.toml` if it exists, else defaults.
/// Config directory overridable with `YARU_CONFIG_DIR` for tests.
pub fn load() -> YaruConfig {
    let dir = dirs::config_dir().map(|d| d.join("yaru"));
    if let Ok(env_dir) = std::env::var("YARU_CONFIG_DIR") {
        let p = PathBuf::from(env_dir).join("config.toml");
        if p.exists() {
            return parse(&p).unwrap_or_default();
        }
        return YaruConfig::default();
    }
    match dir {
        Some(d) => {
            let p = d.join("config.toml");
            if p.exists() {
                parse(&p).unwrap_or_default()
            } else {
                YaruConfig::default()
            }
        }
        None => YaruConfig::default(),
    }
}

fn parse(path: &Path) -> Option<YaruConfig> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}
