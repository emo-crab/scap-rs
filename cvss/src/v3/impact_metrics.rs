use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
// 机密性影响
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidentialityImpactType {
  High,
  Low,
  None,
}
// 完整性影响
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityImpactType {
  High,
  Low,
  None,
}
// 可用性影响
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AvailabilityImpactType {
  High,
  Low,
  None,
}

impl FromStr for ConfidentialityImpactType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if let Some((p, v)) = s.split_once(':') {
      if !matches!(p, "C" | "I" | "A") {
        return Err(CVSSError::InvalidCVSS {
          value: p.to_string(),
          scope: "ImpactMetricsType prefix".to_string(),
        });
      }
      s = v.to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "ImpactMetricsType".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ImpactMetricsType".to_string(),
      }),
    }
  }
}
impl FromStr for IntegrityImpactType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if let Some((p, v)) = s.split_once(':') {
      if !matches!(p, "C" | "I" | "A") {
        return Err(CVSSError::InvalidCVSS {
          value: p.to_string(),
          scope: "ImpactMetricsType prefix".to_string(),
        });
      }
      s = v.to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "ImpactMetricsType".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ImpactMetricsType".to_string(),
      }),
    }
  }
}
impl FromStr for AvailabilityImpactType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if let Some((p, v)) = s.split_once(':') {
      if !matches!(p, "C" | "I" | "A") {
        return Err(CVSSError::InvalidCVSS {
          value: p.to_string(),
          scope: "ImpactMetricsType prefix".to_string(),
        });
      }
      s = v.to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "ImpactMetricsType".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ImpactMetricsType".to_string(),
      }),
    }
  }
}

impl Display for ConfidentialityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for ConfidentialityImpactType {
  const NAME: &'static str = "C";

  fn score(&self) -> f32 {
    match self {
      ConfidentialityImpactType::None => 0.0,
      ConfidentialityImpactType::Low => 0.22,
      ConfidentialityImpactType::High => 0.56,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      ConfidentialityImpactType::None => "N",
      ConfidentialityImpactType::Low => "L",
      ConfidentialityImpactType::High => "H",
    }
  }
}

impl Display for IntegrityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for IntegrityImpactType {
  const NAME: &'static str = "I";

  fn score(&self) -> f32 {
    match self {
      IntegrityImpactType::None => 0.0,
      IntegrityImpactType::Low => 0.22,
      IntegrityImpactType::High => 0.56,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      IntegrityImpactType::None => "N",
      IntegrityImpactType::Low => "L",
      IntegrityImpactType::High => "H",
    }
  }
}

impl Display for AvailabilityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for AvailabilityImpactType {
  const NAME: &'static str = "A";

  fn score(&self) -> f32 {
    match self {
      AvailabilityImpactType::None => 0.0,
      AvailabilityImpactType::Low => 0.22,
      AvailabilityImpactType::High => 0.56,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AvailabilityImpactType::None => "N",
      AvailabilityImpactType::Low => "L",
      AvailabilityImpactType::High => "H",
    }
  }
}
