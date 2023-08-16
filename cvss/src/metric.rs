//! 7.4. Metric Values
//!
//! Each metric value has an associated constant which is used in the formulas, as defined in Table 16.
//!
//! **Table 16: Metric values**
//!
//!
//! | Metric | Metric Value | Numerical Value |
//! | --- | --- | --- |
//! | Attack Vector / Modified Attack Vector | Network | 0.85 |
//! |  | Adjacent | 0.62 |
//! |  | Local | 0.55 |
//! |  | Physical | 0.2 |
//! | Attack Complexity / Modified Attack Complexity | Low | 0.77 |
//! |  | High | 0.44 |
//! | Privileges Required / Modified Privileges Required | None | 0.85 |
//! |  | Low | 0.62 (or 0.68 if Scope / Modified Scope is Changed) |
//! |  | High | 0.27 (or 0.5 if Scope / Modified Scope is Changed) |
//! | User Interaction / Modified User Interaction | None | 0.85 |
//! |  | Required | 0.62 |
//! | Confidentiality / Integrity / Availability / Modified Confidentiality / Modified Integrity / Modified Availability | High | 0.56 |
//! |  | Low | 0.22 |
//! |  | None | 0 |
//! | Exploit Code Maturity | Not Defined | 1 |
//! |  | High | 1 |
//! |  | Functional | 0.97 |
//! |  | Proof of Concept | 0.94 |
//! |  | Unproven | 0.91 |
//! | Remediation Level | Not Defined | 1 |
//! |  | Unavailable | 1 |
//! |  | Workaround | 0.97 |
//! |  | Temporary Fix | 0.96 |
//! |  | Official Fix | 0.95 |
//! | Report Confidence | Not Defined | 1 |
//! |  | Confirmed | 1 |
//! |  | Reasonable | 0.96 |
//! |  | Unknown | 0.92 |
//! | Confidentiality Requirement / Integrity Requirement / Availability Requirement | Not Defined | 1 |
//! |  | High | 1.5 |
//! |  | Medium | 1 |
//! |  | Low | 0.5 |[](#body)
//!
use crate::error::{CVSSError, Result};
use std::fmt::{Debug, Display};
use std::str::FromStr;

pub trait Metric: Clone + Debug + FromStr + Display {
  const TYPE: MetricType;
  fn name() -> &'static str {
    match Self::TYPE {
      MetricType::V2(v2) => v2.name(),
      MetricType::V3(v3) => v3.name(),
    }
  }
  fn description() -> String {
    match Self::TYPE {
      MetricType::V2(v2) => v2.description().to_string(),
      MetricType::V3(v3) => v3.description().to_string(),
    }
  }
  fn score(&self) -> f32;
  fn as_str(&self) -> &'static str;
}
pub enum MetricType {
  V2(MetricTypeV2),
  V3(MetricTypeV3),
}

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
  pub fn description(self) -> &'static str {
    match self {
      Self::AC => "Attack Complexity",
      Self::AV => "Attack Vector",
      Self::PR => "Privileges Required",
      Self::S => "Scope",
      Self::UI => "User Interaction",
      Self::C => "Confidentiality Impact",
      Self::I => "Integrity Impact",
      Self::A => "Availability Impact",
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
  pub fn description(self) -> &'static str {
    match self {
      Self::AC => "Attack Complexity",
      Self::AV => "Attack Vector",
      Self::Au => "Authentication",
      Self::C => "Confidentiality Impact",
      Self::I => "Integrity Impact",
      Self::A => "Availability Impact",
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
