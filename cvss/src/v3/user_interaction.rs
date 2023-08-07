use std::fmt::{Display, Formatter};
use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::metric::Metric;

// UI
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteractionType {
  // UI:R
  Required,
  // UI:N
  None,
}

impl Display for UserInteractionType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for UserInteractionType {
  const NAME: &'static str = "UI";

  fn score(&self) -> f32 {
    match self {
      UserInteractionType::Required => 0.62,
      UserInteractionType::None => 0.85,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      UserInteractionType::Required => "R",
      UserInteractionType::None => "N",
    }
  }
}

impl FromStr for UserInteractionType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("UI:") {
      s = s.strip_prefix("UI:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "UserInteractionType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'R' => Ok(Self::Required),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "UserInteractionType".to_string(),
      }),
    }
  }
}
