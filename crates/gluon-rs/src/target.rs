#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityTarget {
    pub upstream_repo: &'static str,
    pub upstream_commit: String,
    pub upstream_store_package: &'static str,
}

impl CompatibilityTarget {
    pub fn pinned(commit: impl Into<String>) -> Self {
        Self {
            upstream_repo: "https://github.com/ProtonMail/gluon",
            upstream_commit: commit.into(),
            upstream_store_package: "github.com/ProtonMail/gluon/store",
        }
    }
}

impl Default for CompatibilityTarget {
    fn default() -> Self {
        Self::pinned("unversioned-draft")
    }
}
