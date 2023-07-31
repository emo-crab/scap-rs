// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json

pub mod v3 {
  use std::fmt;
  use std::fmt::Formatter;
  use std::str::FromStr;
  // https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  use crate::error::{CVEError, Result};
  use serde::{Deserialize, Serialize};




  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ImpactMetricsType {
    High,
    Low,
    None,
  }
  impl FromStr for ImpactMetricsType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self> {
      let mut s = s.to_uppercase();
      if let Some((p, v)) = s.split_once(':') {
        if !matches!(p, "C" | "I" | "A") {
          return Err(CVEError::InvalidCVSS {
            value: p.to_string(),
            scope: "ImpactMetricsType prefix".to_string(),
          });
        }
        s = v.to_string();
      }
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s,
          scope: "ImpactMetricsType".to_string(),
        })?
      };
      match c {
        'N' => Ok(Self::None),
        'L' => Ok(Self::Low),
        'H' => Ok(Self::High),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "ImpactMetricsType".to_string(),
        }),
      }
    }
  }
  // S
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ScopeType {
    // S:U
    Unchanged,
    // S:C
    Changed,
  }
  impl FromStr for ScopeType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self> {
      let mut s = s.to_uppercase();
      if s.starts_with("S:") {
        s = s.strip_prefix("S:").unwrap_or_default().to_string();
      }
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s,
          scope: "ScopeType from_str".to_string(),
        })?
      };
      match c {
        'U' => Ok(Self::Unchanged),
        'C' => Ok(Self::Changed),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "ScopeType".to_string(),
        }),
      }
    }
  }
  // 严重性
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum SeverityType {
    // 未校正
    None,
    // 低危
    Low,
    // 中危
    Medium,
    // 高危
    High,
    // 严重
    Critical,
  }
  impl FromStr for SeverityType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self> {
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s.to_string(),
          scope: "SeverityType from_str".to_string(),
        })?
      };
      match c {
        'N' => Ok(Self::None),
        'L' => Ok(Self::Low),
        'M' => Ok(Self::Medium),
        'H' => Ok(Self::High),
        'C' => Ok(Self::Critical),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "SeverityType".to_string(),
        }),
      }
    }
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub enum Version {
    None,
    #[serde(rename = "2.0")]
    V2_0,
    #[serde(rename = "3.0")]
    V3_0,
    #[serde(rename = "3.1")]
    V3_1,
    // todo V4
  }

  impl Default for Version {
    fn default() -> Self {
      Version::None
    }
  }
  impl FromStr for Version {
    type Err = CVEError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
      let mut s = s.to_uppercase();
      if s.starts_with("CVSS:") {
        s = s.strip_prefix("CVSS:").unwrap_or_default().to_string();
      }
      match s.as_str() {
        "2.0" => Ok(Self::V2_0),
        "3.0" => Ok(Self::V3_0),
        "3.1" => Ok(Self::V3_1),
        _ => Ok(Self::None),
      }
    }
  }
  impl fmt::Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
      match self {
        Version::None => write!(f, "NONE"),
        Version::V2_0 => write!(f, "2.0"),
        Version::V3_0 => write!(f, "3.0"),
        Version::V3_1 => write!(f, "3.1"),
      }
    }
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct CVSS {
    // 版本： 3.0 和 3.1
    pub version: Version,
    // 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    pub vector_string: String,
    // 访问途径（AV）
    pub attack_vector: AttackVectorType,
    // 攻击复杂度（AC）
    pub attack_complexity: AttackComplexityType,
    // 所需权限（PR）
    pub privileges_required: PrivilegesRequiredType,
    // 用户交互（UI）
    pub user_interaction: UserInteractionType,
    // 影响范围（S）
    pub scope: ScopeType,
    // 机密性影响（C）
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    pub base_score: f64,
    // 基础评级
    pub base_severity: SeverityType,
  }

  impl CVSS {
    // https://nvd.nist.gov/vuln-metrics/cvss
    fn update_severity(&self) {}
    fn update_score(&mut self) {
      self.base_score = 0 as f64;
    }
  }
  impl FromStr for CVSS {
    type Err = CVEError;
    fn from_str(vector_string: &str) -> Result<Self> {
      let (version, vectors) = match vector_string.split_once('/') {
        None => {
          return Err(CVEError::InvalidPrefix {
            value: vector_string.to_string(),
          })
        }
        Some((v, vector)) => {
          let version = Version::from_str(v).unwrap_or_default();
          (version, vector)
        }
      };
      if matches!(version, Version::None) {
        return Err(CVEError::InvalidCVSSVersion {
          value: version.to_string(),
          expected: "2.0, 3.0 or 3.1".to_string(),
        });
      }
      let mut vector = vectors.split('/');
      // "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
      let error = CVEError::InvalidCVSS {
        value: vector_string.to_string(),
        scope: "CVSS parser".to_string(),
      };
      let mut cvss = CVSS {
        version,
        vector_string: vector_string.to_string(),
        attack_vector: AttackVectorType::from_str(vector.next().ok_or(&error)?)?,
        attack_complexity: AttackComplexityType::from_str(vector.next().ok_or(&error)?)?,
        privileges_required: PrivilegesRequiredType::from_str(vector.next().ok_or(&error)?)?,
        user_interaction: UserInteractionType::from_str(vector.next().ok_or(&error)?)?,
        scope: ScopeType::from_str(vector.next().ok_or(&error)?)?,
        confidentiality_impact: ImpactMetricsType::from_str(vector.next().ok_or(&error)?)?,
        integrity_impact: ImpactMetricsType::from_str(vector.next().ok_or(&error)?)?,
        availability_impact: ImpactMetricsType::from_str(vector.next().ok_or(&error)?)?,
        base_score: 0.0,
        base_severity: SeverityType::None,
      };
      cvss.update_score();
      cvss.update_severity();
      Ok(cvss)
    }
  }
}

pub mod v2 {
  use std::str::FromStr;
  // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
  use crate::error::CVEError;
  use serde::{Deserialize, Serialize};

  // AV
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
  pub enum AccessVectorType {
    // AV:N
    Network,
    // AV:A
    AdjacentNetwork,
    // AV:L
    Local,
  }
  impl FromStr for AccessVectorType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s.to_string(),
          scope: "AccessVectorType from_str".to_string(),
        })?
      };
      match c {
        'N' => Ok(Self::Network),
        'A' => Ok(Self::AdjacentNetwork),
        'L' => Ok(Self::Local),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "AccessVectorType".to_string(),
        }),
      }
    }
  }
  // AC
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum AccessComplexityType {
    // AC:H
    High,
    // AC:M
    Medium,
    // AC:L
    Low,
  }
  impl FromStr for AccessComplexityType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s.to_string(),
          scope: "AccessComplexityType from_str".to_string(),
        })?
      };
      match c {
        'H' => Ok(Self::High),
        'M' => Ok(Self::Medium),
        'L' => Ok(Self::Low),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "AccessComplexityType".to_string(),
        }),
      }
    }
  }
  // Au
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum AuthenticationType {
    // Au:M
    Multiple,
    // Au:S
    Single,
    // Au:N
    None,
  }
  impl FromStr for AuthenticationType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s.to_string(),
          scope: "AuthenticationType from_str".to_string(),
        })?
      };
      match c {
        'M' => Ok(Self::Multiple),
        'S' => Ok(Self::Single),
        'N' => Ok(Self::None),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "AuthenticationType".to_string(),
        }),
      }
    }
  }
  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ImpactMetricsType {
    None,
    Partial,
    Complete,
  }
  impl FromStr for ImpactMetricsType {
    type Err = CVEError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      let c = {
        let c = s.to_uppercase().chars().next();
        c.ok_or(CVEError::InvalidCVSS {
          value: s.to_string(),
          scope: "ImpactMetricsType from_str".to_string(),
        })?
      };
      match c {
        'N' => Ok(Self::None),
        'A' => Ok(Self::Partial),
        'L' => Ok(Self::Complete),
        _ => Err(CVEError::InvalidCVSS {
          value: c.to_string(),
          scope: "ImpactMetricsType".to_string(),
        }),
      }
    }
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct CVSS {
    // 版本
    pub version: String,
    // 向量: CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C
    pub vector_string: String,
    // 访问向量
    pub access_vector: AccessVectorType,
    // 访问复杂性
    pub access_complexity: AccessComplexityType,
    // 认证
    pub authentication: AuthenticationType,
    // 完整性影响（I）
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    pub base_score: f64,
  }
}