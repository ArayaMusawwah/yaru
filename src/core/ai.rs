use crate::config::AiConfig;
use crate::core::types::Finding;
use crate::storage::sqlite::Database;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiVerdict {
    Benign,
    Suspicious,
    Malicious,
    Inconclusive,
}

impl AiVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Benign => "Benign",
            Self::Suspicious => "Suspicious",
            Self::Malicious => "Malicious",
            Self::Inconclusive => "Inconclusive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTriageReport {
    pub package: String,
    pub verdict: AiVerdict,
    pub confidence: String,
    pub summary: String,
    pub risk_analysis: Vec<String>,
    pub recommendation: String,
    #[serde(default)]
    pub cached: bool,
}

#[derive(Debug, Error)]
pub enum AiError {
    #[error("AI service disabled in configuration")]
    Disabled,
    #[error("network request error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("database error: {0}")]
    Database(#[from] crate::storage::sqlite::StorageError),
    #[error("failed to parse AI response: {0}")]
    Parse(String),
    #[error("AI API returned error: {0}")]
    Api(String),
}

/// Compute a deterministic SHA-256 fingerprint for a package's findings and reasons.
pub fn compute_findings_fingerprint(
    package: &str,
    findings: &[Finding],
    reasons: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package.as_bytes());
    hasher.update(b"\0");

    let mut sorted_findings: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "{}:{}:{}:{}:{}",
                f.rule_id,
                f.file,
                f.line,
                f.title,
                f.excerpt.trim()
            )
        })
        .collect();
    sorted_findings.sort();
    for f in sorted_findings {
        hasher.update(f.as_bytes());
        hasher.update(b"\n");
    }

    let mut sorted_reasons = reasons.to_vec();
    sorted_reasons.sort();
    for r in sorted_reasons {
        hasher.update(r.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finalize())
}

/// Build system prompt and user prompt for LLM triage.
pub fn build_prompt(
    package: &str,
    findings: &[Finding],
    reasons: &[String],
    language: &str,
) -> (String, String) {
    let lang_instruction = match language.to_ascii_lowercase().as_str() {
        "id" => {
            "Gunakan Bahasa Indonesia yang ringkas, jelas, dan santai untuk summary, risk_analysis, dan recommendation."
        }
        _ => {
            "Use clear, concise, professional English for summary, risk_analysis, and recommendation."
        }
    };

    let system_prompt = format!(
        "You are an expert Arch Linux / AUR security analyst assisting a system administrator with supply-chain triage.\n\
        Evaluate whether the static/source findings in the package are benign packaging conventions, suspicious, or malicious.\n\
        Notice packaging conventions: user warnings in echo/printf, legitimate upstream source downloads, or expected systemd units.\n\
        Watch for genuine supply-chain risks: curl/wget piping to bash, unpinned remote downloads, arbitrary cron jobs, or obfuscated payloads.\n\
        {}\n\
        Output ONLY valid JSON matching this schema:\n\
        {{\n  \
          \"verdict\": \"Benign\" | \"Suspicious\" | \"Malicious\" | \"Inconclusive\",\n  \
          \"confidence\": \"High\" | \"Medium\" | \"Low\",\n  \
          \"summary\": \"One-sentence high-level assessment\",\n  \
          \"risk_analysis\": [\"bullet point 1\", \"bullet point 2\"],\n  \
          \"recommendation\": \"Clear actionable recommendation for the user (allow, skip, or inspect closely)\"\n\
        }}",
        lang_instruction
    );

    let mut user_prompt = format!("Package: {}\n\nEvidence & Reasons:\n", package);
    for r in reasons {
        user_prompt.push_str(&format!("- {}\n", r));
    }

    user_prompt.push_str("\nStatic Findings:\n");
    if findings.is_empty() {
        user_prompt.push_str("  (None)\n");
    } else {
        for f in findings {
            user_prompt.push_str(&format!(
                "- [{:?}] {}:{} · {}\n",
                f.severity, f.file, f.line, f.title
            ));
            if !f.excerpt.trim().is_empty() {
                user_prompt.push_str(&format!("  Snippet: {}\n", f.excerpt.trim()));
            }
        }
    }

    (system_prompt, user_prompt)
}

/// Parse LLM raw text response into `AiTriageReport`.
pub fn parse_ai_response(
    package: &str,
    raw_response: &str,
    cached: bool,
) -> Result<AiTriageReport, AiError> {
    let clean = raw_response.trim();
    // Strip markdown code block wrappers if present: ```json ... ```
    let json_str = if clean.starts_with("```") {
        let without_prefix = clean.trim_start_matches("```");
        let without_lang = if without_prefix.starts_with("json\n")
            || without_prefix.starts_with("json\r\n")
            || without_prefix.starts_with("JSON\n")
        {
            without_prefix
                .split_once('\n')
                .map(|x| x.1)
                .unwrap_or(without_prefix)
        } else {
            without_prefix
        };
        without_lang
            .rsplit_once("```")
            .map(|x| x.0)
            .unwrap_or(without_lang)
            .trim()
    } else {
        clean
    };

    #[derive(Deserialize)]
    struct RawTriage {
        verdict: String,
        confidence: String,
        summary: String,
        risk_analysis: Vec<String>,
        recommendation: String,
    }

    let parsed: RawTriage = serde_json::from_str(json_str).map_err(|e| {
        AiError::Parse(format!(
            "invalid JSON from AI ({e}):\n{}",
            if clean.len() > 200 {
                &clean[..200]
            } else {
                clean
            }
        ))
    })?;

    let verdict = match parsed.verdict.trim().to_ascii_lowercase().as_str() {
        "benign" => AiVerdict::Benign,
        "suspicious" => AiVerdict::Suspicious,
        "malicious" => AiVerdict::Malicious,
        _ => AiVerdict::Inconclusive,
    };

    Ok(AiTriageReport {
        package: package.to_string(),
        verdict,
        confidence: parsed.confidence,
        summary: parsed.summary,
        risk_analysis: parsed.risk_analysis,
        recommendation: parsed.recommendation,
        cached,
    })
}

/// Query an OpenAI-compatible `/chat/completions` endpoint.
async fn query_chat_completions(
    config: &AiConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String, AiError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()?;

    let mut url = config.base_url.trim_end_matches('/').to_string();
    if !url.ends_with("/chat/completions") {
        url.push_str("/chat/completions");
    }

    let payload = serde_json::json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ],
        "temperature": 0.1,
        "stream": false,
        "response_format": { "type": "json_object" }
    });

    let mut req = client.post(&url).json(&payload);
    if let Some(key) = config.resolved_api_key() {
        req = req.header("Authorization", format!("Bearer {}", key));
    }

    let resp = req.send().await?;
    let status = resp.status();
    let body_text = resp.text().await?;

    if !status.is_success() {
        return Err(AiError::Api(format!("HTTP {} — {}", status, body_text)));
    }

    #[derive(Deserialize)]
    struct ChatChoice {
        message: ChatMessage,
    }
    #[derive(Deserialize)]
    struct ChatMessage {
        content: String,
    }
    #[derive(Deserialize)]
    struct ChatResponse {
        choices: Vec<ChatChoice>,
    }

    let chat: Result<ChatResponse, _> = serde_json::from_str(&body_text);
    if let Ok(chat) = chat
        && let Some(choice) = chat.choices.into_iter().next()
    {
        return Ok(choice.message.content);
    }

    // Fallback: If server responded with SSE (text/event-stream)
    let mut collected = String::new();
    for line in body_text.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data == "[DONE]" || data.is_empty() {
                continue;
            }
            #[derive(Deserialize)]
            struct ChunkChoice {
                delta: ChunkDelta,
            }
            #[derive(Deserialize)]
            struct ChunkDelta {
                content: Option<String>,
            }
            #[derive(Deserialize)]
            struct ChunkResponse {
                choices: Vec<ChunkChoice>,
            }
            if let Ok(chunk) = serde_json::from_str::<ChunkResponse>(data) {
                for c in chunk.choices {
                    if let Some(content) = c.delta.content {
                        collected.push_str(&content);
                    }
                }
            }
        }
    }

    if !collected.trim().is_empty() {
        return Ok(collected);
    }

    Err(AiError::Parse(format!(
        "unexpected AI response body:\n{}",
        if body_text.len() > 300 {
            &body_text[..300]
        } else {
            &body_text
        }
    )))
}

/// Triage package findings using AI with persistent SQLite caching.
pub async fn triage_package_cached(
    db: &Database,
    config: &AiConfig,
    package: &str,
    findings: &[Finding],
    reasons: &[String],
    force_refresh: bool,
) -> Result<AiTriageReport, AiError> {
    if !config.enabled {
        return Err(AiError::Disabled);
    }

    let fingerprint = compute_findings_fingerprint(package, findings, reasons);
    let max_age_seconds = (config.cache_ttl_hours * 3600) as i64;

    // Check cache first if refresh not requested
    if !force_refresh
        && let Ok(Some(cached_json)) =
            db.get_valid_ai_triage(package, &fingerprint, &config.model, max_age_seconds)
        && let Ok(report) = parse_ai_response(package, &cached_json, true)
    {
        return Ok(report);
    }

    // Cache miss or force refresh: call AI service
    let (system_prompt, user_prompt) = build_prompt(package, findings, reasons, &config.language);
    let raw = query_chat_completions(config, &system_prompt, &user_prompt).await?;
    let report = parse_ai_response(package, &raw, false)?;

    // Store in cache
    let _ = db.save_ai_triage(package, &fingerprint, &config.model, &raw);

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Severity;

    #[test]
    fn computes_stable_findings_fingerprint() {
        let f1 = Finding {
            rule_id: "SHELL_EXEC".into(),
            title: "Remote Shell Download".into(),
            category: "Execution".into(),
            severity: Severity::Critical,
            file: "winpodx.install".into(),
            line: 53,
            excerpt: "curl -fsSL https://.../uninstall.sh | bash".into(),
            scope: crate::core::types::FindingScope::Install,
        };
        let fp1 =
            compute_findings_fingerprint("winpodx", std::slice::from_ref(&f1), &["reason1".into()]);
        let fp2 = compute_findings_fingerprint("winpodx", &[f1], &["reason1".into()]);
        assert_eq!(fp1, fp2);
        assert!(!fp1.is_empty());
    }

    #[test]
    fn builds_structured_prompt_with_findings() {
        let finding = Finding {
            rule_id: "SHELL_EXEC".into(),
            title: "Remote Shell Download".into(),
            category: "Execution".into(),
            severity: Severity::Critical,
            file: "winpodx.install".into(),
            line: 53,
            excerpt: "curl -fsSL https://.../uninstall.sh | bash".into(),
            scope: crate::core::types::FindingScope::Install,
        };
        let (system, user) =
            build_prompt("winpodx", &[finding], &["Critical curl|bash".into()], "id");
        assert!(system.contains("Arch Linux"));
        assert!(system.contains("Bahasa Indonesia"));
        assert!(user.contains("winpodx.install:53"));
        assert!(user.contains("curl -fsSL"));
    }

    #[test]
    fn parses_ai_triage_json_response() {
        let json_resp = r#"{
            "verdict": "Suspicious",
            "confidence": "High",
            "summary": "Pola uninstaller mengunduh skrip shell dari URL remote.",
            "risk_analysis": ["Eksekusi remote shell berisiko jika server remote disusupi."],
            "recommendation": "Disarankan skip package ini kecuali URL remote diverifikasi."
        }"#;
        let report = parse_ai_response("winpodx", json_resp, false).unwrap();
        assert_eq!(report.verdict, AiVerdict::Suspicious);
        assert_eq!(report.confidence, "High");
        assert!(!report.cached);
        assert_eq!(report.risk_analysis.len(), 1);
    }

    #[test]
    fn parses_ai_response_with_markdown_fence() {
        let wrapped = r#"```json
        {
            "verdict": "Benign",
            "confidence": "Medium",
            "summary": "Pesan informasi ramah pengguna.",
            "risk_analysis": ["Hanya echo instruksi terminal."],
            "recommendation": "Aman untuk dilanjutkan."
        }
        ```"#;
        let report = parse_ai_response("anydesk-bin", wrapped, true).unwrap();
        assert_eq!(report.verdict, AiVerdict::Benign);
        assert!(report.cached);
    }

    #[tokio::test]
    async fn triage_cached_returns_cached_report_on_hit() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("yaru_ai_test.db")).unwrap();
        let config = AiConfig::default();

        let pkg = "winpodx";
        let findings = vec![Finding {
            rule_id: "SHELL_EXEC".into(),
            title: "Remote Shell Download".into(),
            category: "Execution".into(),
            severity: Severity::Critical,
            file: "winpodx.install".into(),
            line: 53,
            excerpt: "curl -fsSL https://.../uninstall.sh | bash".into(),
            scope: crate::core::types::FindingScope::Install,
        }];
        let reasons = vec!["critical remote execution".into()];

        let fp = compute_findings_fingerprint(pkg, &findings, &reasons);
        let stored_json = r#"{
            "verdict": "Suspicious",
            "confidence": "High",
            "summary": "Cached analysis for winpodx",
            "risk_analysis": ["Cached risk detail"],
            "recommendation": "Cached recommendation"
        }"#;

        db.save_ai_triage(pkg, &fp, &config.model, stored_json)
            .unwrap();

        // Should return cached result without hitting network
        let report = triage_package_cached(&db, &config, pkg, &findings, &reasons, false)
            .await
            .unwrap();

        assert_eq!(report.verdict, AiVerdict::Suspicious);
        assert_eq!(report.summary, "Cached analysis for winpodx");
        assert!(report.cached);
    }
}
