use crate::core::types::{MaintainerChange, MaintainerChangeKind, PackageSnapshot, Severity};

pub fn detect_change(
    previous: &PackageSnapshot,
    current: &PackageSnapshot,
) -> Option<MaintainerChange> {
    let prev = previous.maintainer.as_deref();
    let curr = current.maintainer.as_deref();

    let (kind, severity) = match (prev, curr) {
        (Some(a), Some(b)) if a != b => (MaintainerChangeKind::Changed, Severity::High),
        (Some(_), None) => (MaintainerChangeKind::Orphaned, Severity::Medium),
        (None, Some(_)) => (MaintainerChangeKind::Adopted, Severity::High),
        _ => return None,
    };

    Some(MaintainerChange {
        package: current.package_name.clone(),
        previous: previous.maintainer.clone(),
        current: current.maintainer.clone(),
        kind,
        severity,
    })
}

pub fn change_score(changes: &[MaintainerChange]) -> u32 {
    let sum: u32 = changes.iter().map(|c| c.severity.weight()).sum();
    sum.min(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_snapshot(name: &str, maintainer: Option<&str>) -> PackageSnapshot {
        PackageSnapshot {
            package_name: name.to_string(),
            version: Some("1.0".to_string()),
            maintainer: maintainer.map(|s| s.to_string()),
            pkgbuild_hash: "abcd".to_string(),
            source_urls: vec![],
            depends: vec![],
            makedepends: vec![],
            checkdepends: vec![],
            timestamp: 0,
        }
    }

    #[test]
    fn maintainer_changed() {
        let prev = dummy_snapshot("pkg", Some("alice"));
        let curr = dummy_snapshot("pkg", Some("bob"));
        let change = detect_change(&prev, &curr).expect("should detect change");
        assert_eq!(change.kind, MaintainerChangeKind::Changed);
        assert_eq!(change.severity, Severity::High);
        assert_eq!(change.previous.as_deref(), Some("alice"));
        assert_eq!(change.current.as_deref(), Some("bob"));
    }

    #[test]
    fn maintainer_orphaned() {
        let prev = dummy_snapshot("pkg", Some("alice"));
        let curr = dummy_snapshot("pkg", None);
        let change = detect_change(&prev, &curr).expect("should detect change");
        assert_eq!(change.kind, MaintainerChangeKind::Orphaned);
        assert_eq!(change.severity, Severity::Medium);
        assert_eq!(change.previous.as_deref(), Some("alice"));
        assert_eq!(change.current, None);
    }

    #[test]
    fn maintainer_adopted() {
        let prev = dummy_snapshot("pkg", None);
        let curr = dummy_snapshot("pkg", Some("alice"));
        let change = detect_change(&prev, &curr).expect("should detect change");
        assert_eq!(change.kind, MaintainerChangeKind::Adopted);
        assert_eq!(change.severity, Severity::High);
        assert_eq!(change.previous, None);
        assert_eq!(change.current.as_deref(), Some("alice"));
    }

    #[test]
    fn maintainer_unchanged() {
        let prev = dummy_snapshot("pkg", Some("alice"));
        let curr = dummy_snapshot("pkg", Some("alice"));
        assert!(detect_change(&prev, &curr).is_none());

        let prev_none = dummy_snapshot("pkg", None);
        let curr_none = dummy_snapshot("pkg", None);
        assert!(detect_change(&prev_none, &curr_none).is_none());
    }

    #[test]
    fn score_calculation_and_cap() {
        assert_eq!(change_score(&[]), 0);

        let c1 = MaintainerChange {
            package: "pkg1".to_string(),
            previous: None,
            current: Some("a".to_string()),
            kind: MaintainerChangeKind::Adopted,
            severity: Severity::High, // 30
        };
        assert_eq!(change_score(std::slice::from_ref(&c1)), 30);

        let c2 = MaintainerChange {
            package: "pkg2".to_string(),
            previous: Some("a".to_string()),
            current: None,
            kind: MaintainerChangeKind::Orphaned,
            severity: Severity::Medium, // 15
        };
        assert_eq!(change_score(&[c1.clone(), c2.clone()]), 45);

        let c3 = MaintainerChange {
            package: "pkg3".to_string(),
            previous: Some("a".to_string()),
            current: Some("b".to_string()),
            kind: MaintainerChangeKind::Changed,
            severity: Severity::High, // 30
        };
        // 30 + 15 + 30 = 75, capped at 60
        assert_eq!(change_score(&[c1, c2, c3]), 60);
    }
}
