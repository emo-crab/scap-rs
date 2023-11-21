use crate::error::{CVSSError, Result};
use std::fmt::{Debug, Display};
use std::str::FromStr;

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MetricTypeV2 {
  /// Attack Complexity (AC)
  AC,

  /// Attack Vector (AV)
  AV,

  /// Authentication(Au)
  Au,

  /// Confidentiality Impact (C)
  C,

  /// Integrity Impact (I)
  I,
  /// Availability Impact (A)
  A,
}

impl MetricTypeV2 {
  /// Get the name of this metric (i.e. acronym)
  pub fn name(self) -> &'static str {
    match self {
      Self::A => "A",
      Self::AC => "AC",
      Self::AV => "AV",
      Self::C => "C",
      Self::I => "I",
      Self::Au => "Au",
    }
  }
}

impl Display for MetricTypeV2 {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.name())
  }
}

impl FromStr for MetricTypeV2 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "A" => Ok(Self::A),
      "AC" => Ok(Self::AC),
      "AV" => Ok(Self::AV),
      "C" => Ok(Self::C),
      "I" => Ok(Self::I),
      "Au" => Ok(Self::Au),
      _ => Err(CVSSError::UnknownMetric { name: s.to_owned() }),
    }
  }
}
