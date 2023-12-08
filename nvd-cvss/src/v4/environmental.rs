use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV4, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Environmental {
  /// [`ConfidentialityRequirements`] 机密性影响（C）
  pub confidentiality_requirements: ConfidentialityRequirements,
  /// [`IntegrityRequirements`] 完整性影响（I）
  pub integrity_requirements: IntegrityRequirements,
  /// [`AvailabilityRequirements`] 可用性影响（A）
  pub availability_requirements: AvailabilityRequirements,
}

impl Default for Environmental {
  fn default() -> Self {
    // If CR=X, IR=X or AR=X they will default to the worst case (i.e., CR=H, IR=H and AR=H).
    Environmental {
      confidentiality_requirements: ConfidentialityRequirements::High,
      integrity_requirements: IntegrityRequirements::High,
      availability_requirements: AvailabilityRequirements::High,
    }
  }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidentialityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [ConfidentialityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [ConfidentialityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [ConfidentialityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [IntegrityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [IntegrityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [IntegrityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AvailabilityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [AvailabilityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [AvailabilityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [AvailabilityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}

impl Default for ConfidentialityRequirements {
  fn default() -> Self {
    Self::High
  }
}
impl Default for IntegrityRequirements {
  fn default() -> Self {
    Self::High
  }
}
impl Default for AvailabilityRequirements {
  fn default() -> Self {
    Self::High
  }
}
impl ConfidentialityRequirements {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
}

impl IntegrityRequirements {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
}
impl AvailabilityRequirements {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
}
impl Metric for ConfidentialityRequirements {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::CR);

  fn help(&self) -> Help {
    match self {
      Self::NotDefined => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::High => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Medium => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Low => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::NotDefined => 0.0,
      Self::High => 0.0,
      Self::Medium => 0.1,
      Self::Low => 0.2,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::NotDefined => "X",
      Self::High => "H",
      Self::Medium => "M",
      Self::Low => "L",
    }
  }
}

impl FromStr for ConfidentialityRequirements {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let name = Self::name();
    let s = s.to_uppercase();
    let (_name, v) = s
      .split_once(&format!("{}:", name))
      .ok_or(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: s.to_string(),
        expected: name.to_string(),
      })?;
    let c = v.chars().next();
    match c {
      Some('L') => Ok(Self::Low),
      Some('M') => Ok(Self::Medium),
      Some('H') => Ok(Self::High),
      Some('X') => Ok(Self::NotDefined),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "L,H".to_string(),
      }),
    }
  }
}

impl Display for ConfidentialityRequirements {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for IntegrityRequirements {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::IR);

  fn help(&self) -> Help {
    match self {
      Self::NotDefined => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::High => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Medium => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Low => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::NotDefined => 0.0,
      Self::High => 0.0,
      Self::Medium => 0.1,
      Self::Low => 0.2,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::NotDefined => "X",
      Self::High => "H",
      Self::Medium => "M",
      Self::Low => "L",
    }
  }
}

impl FromStr for IntegrityRequirements {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let name = Self::name();
    let s = s.to_uppercase();
    let (_name, v) = s
      .split_once(&format!("{}:", name))
      .ok_or(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: s.to_string(),
        expected: name.to_string(),
      })?;
    let c = v.chars().next();
    match c {
      Some('L') => Ok(Self::Low),
      Some('M') => Ok(Self::Medium),
      Some('H') => Ok(Self::High),
      Some('X') => Ok(Self::NotDefined),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "L,H".to_string(),
      }),
    }
  }
}

impl Display for IntegrityRequirements {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for AvailabilityRequirements {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::AR);

  fn help(&self) -> Help {
    match self {
      Self::NotDefined => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::High => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Medium => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
      Self::Low => Help {
        worth: Worth::Worst,
        des: "".to_string(),
      },
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::NotDefined => 0.0,
      Self::High => 0.0,
      Self::Medium => 0.1,
      Self::Low => 0.2,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::NotDefined => "X",
      Self::High => "H",
      Self::Medium => "M",
      Self::Low => "L",
    }
  }
}

impl FromStr for AvailabilityRequirements {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let name = Self::name();
    let s = s.to_uppercase();
    let (_name, v) = s
      .split_once(&format!("{}:", name))
      .ok_or(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: s.to_string(),
        expected: name.to_string(),
      })?;
    let c = v.chars().next();
    match c {
      Some('L') => Ok(Self::Low),
      Some('M') => Ok(Self::Medium),
      Some('H') => Ok(Self::High),
      Some('X') => Ok(Self::NotDefined),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "L,H".to_string(),
      }),
    }
  }
}

impl Display for AvailabilityRequirements {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}
