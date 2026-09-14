use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Dependency node with resolution metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub name: String,
    pub is_aur: bool,
    pub is_new: bool,
    pub version_req: Option<String>,
    pub children: Vec<String>,
}

/// Full resolved graph for a package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub root: String,
    pub nodes: HashMap<String, DependencyNode>,
    pub aur_dependencies: Vec<String>,
    pub new_dependencies: Vec<String>,
    pub risk_score: u32,
}

/// Strips version constraints (`>=1.0`, `=2.3`) to isolate the raw package name.
pub fn clean_dep_name(raw: &str) -> String {
    raw.split(['>', '<', '=', ':'])
        .next()
        .unwrap_or(raw)
        .trim()
        .to_string()
}

/// Builds and analyzes dependency risk given raw declared depends and an optional
/// previous snapshot to detect newly introduced dependencies.
pub fn analyze_dependencies(
    root: &str,
    depends: &[String],
    makedepends: &[String],
    previous_depends: Option<&[String]>,
    aur_lookup: impl Fn(&str) -> bool,
) -> DependencyGraph {
    let mut nodes = HashMap::new();
    let mut aur_dependencies = Vec::new();
    let mut new_dependencies = Vec::new();

    let old_set: HashSet<String> = previous_depends
        .unwrap_or(&[])
        .iter()
        .map(|s| clean_dep_name(s))
        .collect();

    let all_deps: Vec<String> = depends
        .iter()
        .chain(makedepends.iter())
        .map(|s| clean_dep_name(s))
        .filter(|s| !s.is_empty())
        .collect();

    for name in &all_deps {
        let is_aur = aur_lookup(name);
        let is_new = !old_set.is_empty() && !old_set.contains(name);

        if is_aur {
            aur_dependencies.push(name.clone());
        }
        if is_new {
            new_dependencies.push(name.clone());
        }

        nodes.insert(
            name.clone(),
            DependencyNode {
                name: name.clone(),
                is_aur,
                is_new,
                version_req: None,
                children: Vec::new(),
            },
        );
    }

    // Risk: each AUR dependency adds 5, each newly added dependency adds 15. Cap at 60.
    let risk_score =
        (aur_dependencies.len() as u32 * 5 + new_dependencies.len() as u32 * 15).min(60);

    DependencyGraph {
        root: root.to_string(),
        nodes,
        aur_dependencies,
        new_dependencies,
        risk_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_versioned_dependency_strings() {
        assert_eq!(clean_dep_name("glibc>=2.34"), "glibc");
        assert_eq!(clean_dep_name("python-numpy=1.23.0"), "python-numpy");
        assert_eq!(clean_dep_name("openssl"), "openssl");
    }

    #[test]
    fn detects_aur_dependencies_correctly() {
        let deps = vec!["glibc".into(), "custom-aur-pkg".into()];
        let g = analyze_dependencies("my-pkg", &deps, &[], None, |name| name == "custom-aur-pkg");
        assert_eq!(g.aur_dependencies, vec!["custom-aur-pkg".to_string()]);
        assert_eq!(g.risk_score, 5);
    }

    #[test]
    fn detects_newly_introduced_dependencies_against_previous_snapshot() {
        let old = vec!["glibc".into()];
        let current = vec!["glibc".into(), "unexpected-lib".into()];
        let g = analyze_dependencies("my-pkg", &current, &[], Some(&old), |_| false);
        assert_eq!(g.new_dependencies, vec!["unexpected-lib".to_string()]);
        assert_eq!(g.risk_score, 15);
    }

    #[test]
    fn score_caps_at_sixty() {
        let deps: Vec<String> = (0..20).map(|i| format!("pkg-{}", i)).collect();
        let g = analyze_dependencies("my-pkg", &deps, &[], None, |_| true);
        assert_eq!(g.risk_score, 60);
    }
}
