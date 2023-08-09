//! 2.3. Impact Metrics
//!
//! The Impact metrics capture the effects of a successfully exploited vulnerability on the component that suffers the worst outcome that is most directly and predictably associated with the attack. Analysts should constrain impacts to a reasonable, final outcome which they are confident an attacker is able to achieve.
//!
//! Only the increase in access, privileges gained, or other negative outcome as a result of successful exploitation should be considered when scoring the Impact metrics of a vulnerability. For example, consider a vulnerability that requires read-only permissions prior to being able to exploit the vulnerability. After successful exploitation, the attacker maintains the same level of read access, and gains write access. In this case, only the Integrity impact metric should be scored, and the Confidentiality and Availability Impact metrics should be set as None.
//!
//! Note that when scoring a delta change in impact, the **final impact** should be used. For example, if an attacker starts with partial access to restricted information (Confidentiality Low) and successful exploitation of the vulnerability results in complete loss in confidentiality (Confidentiality High), then the resultant CVSS Base Score should reference the “end game” Impact metric value (Confidentiality High).
//!
//! If a scope change has not occurred, the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to the vulnerable component. However, if a scope change has occurred, then the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to either the vulnerable component, or the impacted component, whichever suffers the most severe outcome.
//!

use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
/// ### 2.3.1. Confidentiality Impact(C) 机密性影响
///
/// 该指标衡量成功利用漏洞对软件组件管理的信息资源的机密性的影响程度。机密 是指仅限于授权用户访问和披露的信息，以及防止未授权用户访问或披露的信息。
///
/// This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. The Base Score is greatest when the loss to the impacted component is highest. The list of possible values is presented in Table 6.
///
/// **Table 6: Confidentiality**
///
/// | Metric Value | Description |
/// | --- | --- |
/// | High (H) | There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
/// | Low (L) | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component. |
/// | None (N) | There is no loss of confidentiality within the impacted component. |
///
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidentialityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}
/// ### 2.3.2. Integrity Impact(I) 完整性影响
///
/// 该指标衡量成功利用漏洞对完整性的影响程度。完整性 是指信息的可靠性和准确性。
///
/// This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. The Base Score is greatest when the consequence to the impacted component is highest. The list of possible values is presented in Table 7.
///
/// **Table 7: Integrity**
///
/// | Metric Value | Description |
/// | --- | --- |
/// | High (H) | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component. |
/// | Low (L) | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component. |
/// | None (N) | There is no loss of integrity within the impacted component. |
///
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}
/// ### 2.3.3. Availability (A) 可用性影响
///
/// 该指标衡量成功利用漏洞对受影响组件可用性的影响程度。虽然机密性和完整性影响指标适用于受影响组件使用的数据（如信息、文件）的机密性或完整性的损失，但此指标是指受影响组件本身的可用性损失，如网络服务（如Web、数据库、电子邮件）。可用性是指信息资源的可访问性，如消耗网络带宽、处理器周期或磁盘空间的攻击都会影响受影响组件的可用性。
///
/// This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of _data_ (e.g., information, files) used by the impacted component, this metric refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component. The Base Score is greatest when the consequence to the impacted component is highest. The list of possible values is presented in Table 8.
///
/// **Table 8: Availability**
///
/// | Metric Value | Description |
/// | --- | --- |
/// | High (H) | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
/// | Low (L) | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component. |
/// | None (N) | There is no impact to availability within the impacted component. |[](#body)
///
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AvailabilityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}

impl FromStr for ConfidentialityImpactType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with(Self::NAME) {
      s = s
        .strip_prefix(&format!("{}:", Self::NAME))
        .unwrap_or_default()
        .to_string();
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
    if s.starts_with(Self::NAME) {
      s = s
        .strip_prefix(&format!("{}:", Self::NAME))
        .unwrap_or_default()
        .to_string();
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
    if s.starts_with(Self::NAME) {
      s = s
        .strip_prefix(&format!("{}:", Self::NAME))
        .unwrap_or_default()
        .to_string();
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
