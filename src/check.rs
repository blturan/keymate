//! One checked thing, as `doctor`, `devices` and `status` show it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Pass,
    Warn,
    Fail,
    /// A plain fact, shown without a mark, e.g. where a key file is.
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub label: &'static str,
    pub mark: Mark,
    pub detail: String,
    /// What the person can do about a warning or failure.
    pub hint: Option<String>,
}

impl Check {
    pub fn new(label: &'static str, mark: Mark, detail: impl Into<String>) -> Self {
        Check {
            label,
            mark,
            detail: detail.into(),
            hint: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}
