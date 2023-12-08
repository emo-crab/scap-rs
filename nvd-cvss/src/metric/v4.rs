use crate::error::{CVSSError, Result};
use std::fmt::{Debug, Display};
use std::str::FromStr;
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum MetricTypeV4 {
  /// Attack Complexity (AC)
  AC,

  /// Attack Vector (AV)
  AV,

  /// Attack Requirements (AT)
  AT,

  /// Confidentiality Impact (C)
  VC,

  /// Integrity Impact (I)
  VI,

  /// Availability Impact (A)
  VA,

  /// Confidentiality Impact (C)
  SC,

  /// Integrity Impact (I)
  SI,

  /// Availability Impact (A)
  SA,

  /// Privileges Required (PR)
  PR,

  /// User Interaction (UI)
  UI,
  /// Confidentiality Requirements (CR)
  CR,
  /// Integrity Requirements (IR)
  IR,
  /// Availability Requirements (AR)
  AR,
  /// Exploit Maturity (E)
  E,
}

impl MetricTypeV4 {
  /// Get the name of this metric (i.e. acronym)
  pub fn name(self) -> &'static str {
    match self {
      Self::AC => "AC",
      Self::AT => "AT",
      Self::AV => "AV",
      Self::PR => "PR",
      Self::UI => "UI",
      Self::VC => "VC",
      Self::VI => "VI",
      Self::VA => "VA",
      Self::SC => "SC",
      Self::SI => "SI",
      Self::SA => "SA",
      Self::CR => "CR",
      Self::IR => "IR",
      Self::AR => "AR",
      Self::E => "E",
    }
  }
}

impl Display for MetricTypeV4 {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.name())
  }
}

impl FromStr for MetricTypeV4 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "AC" => Ok(Self::AC),
      "AV" => Ok(Self::AV),
      "VC" => Ok(Self::VC),
      "VI" => Ok(Self::VI),
      "VA" => Ok(Self::VA),
      "SC" => Ok(Self::SC),
      "SI" => Ok(Self::SI),
      "SA" => Ok(Self::SA),
      "PR" => Ok(Self::PR),
      "AT" => Ok(Self::AT),
      "UI" => Ok(Self::UI),
      "CR" => Ok(Self::CR),
      "IR" => Ok(Self::IR),
      "AR" => Ok(Self::AR),
      _ => Err(CVSSError::UnknownMetric { name: s.to_owned() }),
    }
  }
}
