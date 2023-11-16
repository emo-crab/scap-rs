use crate::error::{CVSSError, Result};
use std::fmt::{Debug, Display};
use std::str::FromStr;
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MetricTypeV3 {
  /// Availability Impact (A)
  A,

  /// Attack Complexity (AC)
  AC,

  /// Attack Vector (AV)
  AV,

  /// Confidentiality Impact (C)
  C,

  /// Integrity Impact (I)
  I,

  /// Privileges Required (PR)
  PR,

  /// Scope (S)
  S,

  /// User Interaction (UI)
  UI,
}

impl MetricTypeV3 {
  /// Get the name of this metric (i.e. acronym)
  pub fn name(self) -> &'static str {
    match self {
      Self::AC => "AC",
      Self::AV => "AV",
      Self::PR => "PR",
      Self::S => "S",
      Self::UI => "UI",
      Self::C => "C",
      Self::I => "I",
      Self::A => "A",
    }
  }
}

impl Display for MetricTypeV3 {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.name())
  }
}

impl FromStr for MetricTypeV3 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "A" => Ok(Self::A),
      "AC" => Ok(Self::AC),
      "AV" => Ok(Self::AV),
      "C" => Ok(Self::C),
      "I" => Ok(Self::I),
      "PR" => Ok(Self::PR),
      "S" => Ok(Self::S),
      "UI" => Ok(Self::UI),
      _ => Err(CVSSError::UnknownMetric { name: s.to_owned() }),
    }
  }
}
