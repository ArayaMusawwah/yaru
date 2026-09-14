use crate::core::types::{
    Finding, MaintainerChange, RiskLevel, RiskReport, ScoreBreakdown, TrustZone, Verdict,
};

/// Composite risk = sum of signal scores, capped at 100.
/// Deterministic and explainable: evidence decides policy, not popularity.
pub fn assess(
    package: &str,
    zone: TrustZone,
    breakdown: &ScoreBreakdown,
    findings: &[Finding],
    maintainer_changes: &[MaintainerChange],
) -> RiskReport {
    let mut breakdown = breakdown.clone();
    breakdown.source_score = zone.base_risk();
    let finding_weight = findings
        .iter()
        .map(|f| f.severity.weight())
        .sum::<u32>()
        .min(60);
    breakdown.static_score = breakdown.static_score.max(finding_weight);
    let change_weight = maintainer_changes
        .iter()
        .map(|c| c.severity.weight())
        .sum::<u32>()
        .min(60);
    breakdown.change_score = breakdown.change_score.max(change_weight);

    let mut report = RiskReport {
        package: package.to_string(),
        zone,
        breakdown,
        findings: findings.to_vec(),
        maintainer_changes: maintainer_changes.to_vec(),
        verdict: Verdict::Allow,
        reasons: Vec::new(),
    };
    report.verdict = decide(&report);
    report.reasons = explain(&report);
    report
}

pub fn decide(report: &RiskReport) -> Verdict {
    match RiskLevel::from_score(report.score()) {
        RiskLevel::Low => Verdict::Allow,
        RiskLevel::Medium => Verdict::Warn,
        RiskLevel::High => Verdict::Quarantine,
        RiskLevel::Critical => Verdict::Block,
    }
}

pub fn explain(report: &RiskReport) -> Vec<String> {
    let mut reasons = vec![format!("Source zone: {}", report.zone.label())];

    for f in &report.findings {
        reasons.push(format!(
            "{} finding at {}:{} — {}",
            f.severity.label(),
            f.file,
            f.line,
            f.title
        ));
    }

    for ch in &report.maintainer_changes {
        reasons.push(format!(
            "Maintainer {} ({} → {})",
            ch.kind.label(),
            ch.previous.as_deref().unwrap_or("n/a"),
            ch.current.as_deref().unwrap_or("n/a")
        ));
    }

    let b = &report.breakdown;
    reasons.push(format!(
        "Static {}, Change {}, Dep {}, Threat {}, Behavior {}, Source {}",
        b.static_score,
        b.change_score,
        b.dependency_score,
        b.threat_score,
        b.behavior_score,
        b.source_score
    ));

    reasons
}
