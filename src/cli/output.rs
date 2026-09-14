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
