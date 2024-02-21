//! Impact Metrics
//! --------------
//!
//! The Impact metrics capture the effects of a successfully exploited vulnerability. Analysts should constrain impacts to a reasonable, final outcome which they are confident an attacker is able to achieve.
//!
//! Only an increase in access, privileges gained, or other negative outcome as a result of successful exploitation should be considered when assessing the Impact metrics of a vulnerability. For example, consider a vulnerability that requires read-only permissions prior to being able to knowledge_base the vulnerability. After successful exploitation, the attacker maintains the same level of read access, and gains write access. In this case, only the Integrity impact metric should be scored, and the Confidentiality and Availability Impact metrics should be set as None.
//!
//! Note that when scoring a delta change in impact, the **final impact** should be used. For example, if an attacker starts with partial access to restricted information (Confidentiality Low) and successful exploitation of the vulnerability results in complete loss in confidentiality (Confidentiality High), then the resultant CVSS Base metric value should reference the “end game” Impact metric value (Confidentiality High).
//!
//! When identifying values for the impact metrics, assessment providers need to account for impacts both to the Vulnerable System and impacts outside of the Vulnerable System. These impacts are established by two sets of impact metrics: _“Vulnerable System impact”_ and _“Subsequent System impact”_. When establishing the boundaries for the Vulnerable System metric values, assessment providers should use the conceptual model of a system of interest.
//!
//! Formally, a system of interest for scoring a vulnerability is defined as the set of computing logic that executes in an environment with a coherent function and set of security policies. The vulnerability exists in one or more components of such a system. A technology product or a solution that serves a purpose or function from a consumer's perspective is considered a system (e.g., a server, workstation, containerized service, etc.).
//!
//! When a system provides its functionality solely to another system, or it is designed to be exclusively used by another system, then together they are considered as the system of interest for scoring. For example, a database used solely by a smart speaker is considered a part of that smart speaker system. Both the database and the smart speaker it serves would be considered the vulnerable system if a vulnerability in that database leads to the malfunction of the smart speaker. When a vulnerability does not have impact outside of the vulnerable system assessment providers should leave the subsequent system impact metrics as NONE (N).
//!
//! All impacts, if any, that occur outside of the vulnerable system should be reflected in the subsequent system impact set. When assessed in the environmental metric group only, the subsequent system impact may, in addition to the logical systems defined for System of Interest, also include impacts to humans. This human impact option in the environmental metric group is explained further in Safety (S), below.
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV4, Worth};

/// ### Confidentiality (VC/SC) 机密性影响
///
/// 该指标衡量成功利用漏洞对软件组件管理的信息资源的机密性的影响程度。机密 是指仅限于授权用户访问和披露的信息，以及防止未授权用户访问或披露的信息。
///
/// This metric measures the impact to the confidentiality of the information managed by the system due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. The resulting score is greatest when the loss to the system is highest. The list of possible values is presented in Table 6 (for the Vulnerable System) and Table 7 (when there is a Subsequent System impacted).
///
/// ### Table 6: Confidentiality Impact to the Vulnerable System (VC)
///
/// | **Metric Value** | **Description** |
/// | --- | --- |
/// | High (H) | There is a total loss of confidentiality, resulting in all information within the Vulnerable System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server. |
/// | Low (L) | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Vulnerable System. |
/// | None (N) | There is no loss of confidentiality within the Vulnerable System. |
///

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VulnerableConfidentialityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}
/// ### Integrity (VI/SI) 完整性影响
///
/// 该指标衡量成功利用漏洞对完整性的影响程度。完整性 是指信息的可靠性和准确性。
///
/// This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of a system is impacted when an attacker causes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).
///
/// The resulting score is greatest when the consequence to the system is highest. The list of possible values is presented in Table 8 (for the Vulnerable System) and Table 9 (when there is a Subsequent System impacted).
///
///
/// **Table 8: Integrity Impact to the Vulnerable System (VI)**
///
/// | **Metric Value** | **Description** |
/// | --- | --- |
/// | High (H) | There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Vulnerable System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Vulnerable System. |
/// | Low (L) | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System. |
/// | None (N) | There is no loss of integrity within the Vulnerable System. |
///

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VulnerableIntegrityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}
/// ### Availability (VA/SA) 可用性影响
///
/// 该指标衡量成功利用漏洞对受影响组件可用性的影响程度。虽然机密性和完整性影响指标适用于受影响组件使用的数据（如信息、文件）的机密性或完整性的损失，但此指标是指受影响组件本身的可用性损失，如网络服务（如Web、数据库、电子邮件）。可用性是指信息资源的可访问性，如消耗网络带宽、处理器周期或磁盘空间的攻击都会影响受影响组件的可用性。
///
/// This metric measures the impact to the availability of the impacted system resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of _data_ (e.g., information, files) used by the system, this metric refers to the loss of availability of the impacted system itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system. The resulting score is greatest when the consequence to the system is highest. The list of possible values is presented in Table 10 (for the Vulnerable System) and Table 11 (when there is a Subsequent System impacted).
///
/// ### Table 10: Availability Impact to the Vulnerable System (VA)
///
/// | **Metric Value** | **Description** |
/// | --- | --- |
/// | High (H) | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Vulnerable System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly knowledge_base a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
/// | Low (L) | Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System. |
/// | None (N) | There is no impact to availability within the Vulnerable System. |
///

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VulnerableAvailabilityImpactType {
  /// High(H) 高: 高度影响，可能会造成严重的损失。
  High,
  /// Low(L)  低: 低程度影响，总体上不会造成重大损失。
  Low,
  /// None(N) 无: 毫无影响。
  None,
}

impl FromStr for VulnerableConfidentialityImpactType {
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
      Some('N') => Ok(Self::None),
      Some('L') => Ok(Self::Low),
      Some('H') => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,L,H".to_string(),
      }),
    }
  }
}
impl FromStr for VulnerableIntegrityImpactType {
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
      Some('N') => Ok(Self::None),
      Some('L') => Ok(Self::Low),
      Some('H') => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,L,H".to_string(),
      }),
    }
  }
}
impl FromStr for VulnerableAvailabilityImpactType {
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
      Some('N') => Ok(Self::None),
      Some('L') => Ok(Self::Low),
      Some('H') => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,L,H".to_string(),
      }),
    }
  }
}

impl Display for VulnerableConfidentialityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for VulnerableConfidentialityImpactType {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::VC);

  fn help(&self) -> Help {
    match self {
      Self::High => {Help{ worth: Worth::Worst, des: "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.".to_string() }}
      Self::Low => {Help{ worth: Worth::Bad, des: "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no loss of confidentiality within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.2,
      Self::Low => 0.1,
      Self::High => 0.0,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::None => "N",
      Self::Low => "L",
      Self::High => "H",
    }
  }
}

impl Display for VulnerableIntegrityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for VulnerableIntegrityImpactType {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::VI);

  fn help(&self) -> Help {
    match self {
      Self::High => {Help{ worth: Worth::Worst, des: "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.".to_string() }}
      Self::Low => {Help{ worth: Worth::Bad, des: "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no loss of integrity within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.2,
      Self::Low => 0.1,
      Self::High => 0.0,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::None => "N",
      Self::Low => "L",
      Self::High => "H",
    }
  }
}

impl Display for VulnerableAvailabilityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for VulnerableAvailabilityImpactType {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::VA);

  fn help(&self) -> Help {
    match self {
      Self::High => { Help { worth: Worth::Worst, des: "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly knowledge_base a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).".to_string() } }
      Self::Low => {Help{ worth: Worth::Bad, des: "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no impact to availability within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.2,
      Self::Low => 0.1,
      Self::High => 0.0,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::None => "N",
      Self::Low => "L",
      Self::High => "H",
    }
  }
}

impl VulnerableConfidentialityImpactType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}

impl VulnerableIntegrityImpactType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl VulnerableAvailabilityImpactType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
/// 2.3. Impact Metrics
///
/// The Impact metrics refer to the properties of the impacted component. Whether a successfully exploited vulnerability affects one or more components, the impact metrics are scored according to the component that suffers the worst outcome that is most directly and predictably associated with a successful attack. That is, analysts should constrain impacts to a reasonable, final outcome which they are confident an attacker is able to achieve.
///
/// If a scope change has not occurred, the Impact metrics should reflect the confidentiality, integrity, and availability (CIA) impact to the vulnerable component. However, if a scope change has occurred, then the Impact metrics should reflect the CIA impact to either the vulnerable component, or the impacted component, whichever suffers the most severe outcome.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VulnerableImpact {
  /// [`VulnerableConfidentialityImpactType`] 机密性影响（C）
  pub confidentiality_impact: VulnerableConfidentialityImpactType,
  /// [`VulnerableIntegrityImpactType`] 完整性影响（I）
  pub integrity_impact: VulnerableIntegrityImpactType,
  /// [`VulnerableAvailabilityImpactType`] 可用性影响（A）
  pub availability_impact: VulnerableAvailabilityImpactType,
}

impl VulnerableIntegrityImpactType {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
  pub(crate) fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }
}
impl VulnerableConfidentialityImpactType {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
  pub(crate) fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }
}
impl VulnerableAvailabilityImpactType {
  pub(crate) fn is_high(&self) -> bool {
    matches!(self, Self::High)
  }
  pub(crate) fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }
}
impl VulnerableImpact {
  pub(crate) fn all_none(&self) -> bool {
    self.confidentiality_impact.is_none()
      && self.integrity_impact.is_none()
      && self.availability_impact.is_none()
  }

  // EQ3: 0-(VC:H and VI:H)
  //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
  //      2-not (VC:H or VI:H or VA:H)
  pub(crate) fn eq3(&self) -> Option<u32> {
    if self.confidentiality_impact.is_high() && self.integrity_impact.is_high() {
      return Some(0);
    } else if !(self.confidentiality_impact.is_high() && self.integrity_impact.is_high())
      && (self.confidentiality_impact.is_high()
        || self.integrity_impact.is_high()
        || self.availability_impact.is_high())
    {
      return Some(1);
    } else if !(self.confidentiality_impact.is_high()
      || self.integrity_impact.is_high()
      || self.availability_impact.is_high())
    {
      return Some(2);
    }
    None
  }
}
