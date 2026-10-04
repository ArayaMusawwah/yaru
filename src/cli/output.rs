use crate::core::types::{Finding, RiskReport, Severity, Verdict};
use colored::Colorize;

/// Every box line is exactly 63 visible columns. Padding is computed, never
/// eyeballed, so columns stay aligned at any terminal width. Color never
/// carries meaning alone (WCAG AA) — tags like [OK]/[X] duplicate it.
const INNER: usize = 59;

fn row(label: &str, content: &str) -> String {
    format!("│ {:<12} {:<46} │", label, content)
}

fn bare_row(content: &str) -> String {
    format!("│ {:<width$} │", content, width = INNER)
}

fn banner_line(left: char, title: &str, right: char) -> String {
    format!("{left}{title:^width$}{right}", width = INNER)
}

pub fn print_banner() {
    println!("{}", format!("┌{}┐", "─".repeat(INNER)).dimmed());
    println!(
        "{}",
        banner_line('│', "YARU · AUR Supply-Chain Security Layer ", '│').bold()
    );
    println!("{}", format!("└{}┘", "─".repeat(INNER)).dimmed());
}

pub fn print_report_card(report: &RiskReport) {
    let b = &report.breakdown;
    println!();
    println!(
        "{}",
        format!("┌─ EVALUATION RESULT {}┐", "─".repeat(INNER - 18)).cyan()
    );
    println!("{}", row("Package :", &report.package).white().bold());
    println!(
        "{}",
        row(
            "Zone :",
            &format!("{} ({})", report.zone.label(), report.zone.base_risk())
        )
    );
    println!(
        "{}",
        row(
            "Risk Score :",
            &format!("{}/100 [{}]", report.score(), report.level().label())
        )
    );
    println!("{}", row("Verdict :", &format_verdict(report.verdict)));
    println!(
        "{}",
        format!("├─ SCORE BREAKDOWN {}┤", "─".repeat(INNER - 16)).cyan()
    );
    println!(
        "{}",
        bare_row(&format!(
            "Static {:<3} Change {:<3} Dep {:<3} Threat {:<3} Src {:<3} Behavior {:<3}",
            b.static_score,
            b.change_score,
            b.dependency_score,
            b.threat_score,
            b.source_score,
            b.behavior_score
        ))
    );
    println!("{}", format!("└{}┘", "─".repeat(INNER)).cyan());
}

fn format_verdict(verdict: Verdict) -> String {
    match verdict {
        Verdict::Allow => "[OK] ALLOW".green().bold().to_string(),
        Verdict::Warn => "[!] WARN".yellow().bold().to_string(),
        Verdict::Quarantine => "[?] QUARANTINE".magenta().bold().to_string(),
        Verdict::Block => "[X] BLOCK".red().bold().to_string(),
    }
}

pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!(
            "\n{}",
            "  No suspicious patterns detected in PKGBUILD.".green()
        );
        return;
    }

    println!(
        "\n{}",
        "── Findings ──────────────────────────────────────────────────".yellow()
    );
    for f in findings {
        let tag = match f.severity {
            Severity::Info => "[INFO]    ".dimmed(),
            Severity::Low => "[LOW]     ".blue(),
            Severity::Medium => "[MEDIUM]  ".yellow(),
            Severity::High => "[HIGH]    ".bright_red(),
            Severity::Critical => "[CRITICAL]".red().bold(),
        };
        println!("  {} {}:{} · {}", tag, f.file, f.line, f.title.bold());
        println!("             {}", f.excerpt.trim().dimmed());
    }
}

pub fn print_reasons(reasons: &[String]) {
    println!(
        "\n{}",
        "── Decision Evidence ─────────────────────────────────────────".cyan()
    );
    for (i, r) in reasons.iter().enumerate() {
        println!("  {}. {}", i + 1, r);
    }
}

pub fn print_source_integrity(findings: &[Finding]) {
    let src: Vec<_> = findings
        .iter()
        .filter(|f| f.category == "source-integrity")
        .collect();
    if src.is_empty() {
        return;
    }
    println!(
        "\n{}",
        "── Source Integrity ───────────────────────────────────────────".yellow()
    );
    for f in src {
        let tag = match f.severity {
            Severity::Info => "[INFO]    ".dimmed(),
            Severity::Low => "[LOW]     ".blue(),
            Severity::Medium => "[MEDIUM]  ".yellow(),
            Severity::High => "[HIGH]    ".bright_red(),
            Severity::Critical => "[CRITICAL]".red().bold(),
        };
        println!("  {} {}:{} · {}", tag, f.file, f.line, f.title.bold());
        println!("             {}", f.excerpt.trim().dimmed());
    }
}

pub fn render_ai_triage_to<W: std::io::Write>(
    writer: &mut W,
    report: &crate::core::ai::AiTriageReport,
) -> std::io::Result<()> {
    use crate::core::ai::AiVerdict;

    let cached_badge = if report.cached {
        format!(" {}", "[CACHED]".cyan().bold())
    } else {
        String::new()
    };

    let verdict_badge = match report.verdict {
        AiVerdict::Benign => "[BENIGN]      ".green().bold(),
        AiVerdict::Suspicious => "[SUSPICIOUS]  ".yellow().bold(),
        AiVerdict::Malicious => "[MALICIOUS]   ".red().bold(),
        AiVerdict::Inconclusive => "[INCONCLUSIVE]".cyan().bold(),
    };

    writeln!(
        writer,
        "\n{}",
        "── AI Security Triage ────────────────────────────────────────"
            .bright_magenta()
            .bold()
    )?;
    writeln!(
        writer,
        "  Package       : {}{}",
        report.package.bold().white(),
        cached_badge
    )?;
    writeln!(
        writer,
        "  Verdict       : {} (Confidence: {})",
        verdict_badge,
        report.confidence.bold()
    )?;
    writeln!(writer, "  Summary       : {}", report.summary.trim())?;

    if !report.risk_analysis.is_empty() {
        writeln!(writer, "  Risk Analysis :")?;
        for item in &report.risk_analysis {
            writeln!(writer, "    • {}", item.trim())?;
        }
    }

    writeln!(
        writer,
        "  Recommendation: {}",
        report.recommendation.trim().bold()
    )?;
    writeln!(
        writer,
        "{}",
        "──────────────────────────────────────────────────────────────".dimmed()
    )?;
    Ok(())
}

pub fn print_ai_triage(report: &crate::core::ai::AiTriageReport) {
    let mut out = std::io::stdout().lock();
    let _ = render_ai_triage_to(&mut out, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ai::{AiTriageReport, AiVerdict};

    #[test]
    fn renders_ai_triage_box_with_cached_tag() {
        let report = AiTriageReport {
            package: "winpodx".into(),
            verdict: AiVerdict::Suspicious,
            confidence: "High".into(),
            summary: "Remote shell download in uninstaller.".into(),
            risk_analysis: vec!["Curl pipe bash lacks hash verification.".into()],
            recommendation: "Skip or inspect upstream script.".into(),
            cached: true,
        };
        let mut buf = Vec::new();
        render_ai_triage_to(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("AI Security Triage"));
        assert!(output.contains("winpodx"));
        assert!(output.contains("[CACHED]"));
        assert!(output.contains("[SUSPICIOUS]"));
        assert!(output.contains("Confidence: High"));
        assert!(output.contains("Recommendation"));
    }
}
