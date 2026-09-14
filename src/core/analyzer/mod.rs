pub mod deobfuscate;
pub mod pkgbuild;
pub mod rules;

pub use pkgbuild::{AnalyzerError, PkgbuildAnalysis, analyze_pkgbuild_dir};
pub use rules::{Rule, RuleSet};
