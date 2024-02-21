//! 2.3. Impact Metrics
//!
//! The Impact metrics capture the effects of a successfully exploited vulnerability on the component that suffers the worst outcome that is most directly and predictably associated with the attack. Analysts should constrain impacts to a reasonable, final outcome which they are confident an attacker is able to achieve.
//!
//! Only the increase in access, privileges gained, or other negative outcome as a result of successful exploitation should be considered when scoring the Impact metrics of a vulnerability. For example, consider a vulnerability that requires read-only permissions prior to being able to knowledge_base the vulnerability. After successful exploitation, the attacker maintains the same level of read access, and gains write access. In this case, only the Integrity impact metric should be scored, and the Confidentiality and Availability Impact metrics should be set as None.
//!
//! Note that when scoring a delta change in impact, the **final impact** should be used. For example, if an attacker starts with partial access to restricted information (Confidentiality Low) and successful exploitation of the vulnerability results in complete loss in confidentiality (Confidentiality High), then the resultant CVSS Base Score should reference the “end game” Impact metric value (Confidentiality High).
//!
//! If a scope change has not occurred, the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to the vulnerable component. However, if a scope change has occurred, then the Impact metrics should reflect the Confidentiality, Integrity, and Availability impacts to either the vulnerable component, or the impacted component, whichever suffers the most severe outcome.
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV3, Worth};

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
/// | High (H) | There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly knowledge_base a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable). |
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
impl FromStr for IntegrityImpactType {
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
impl FromStr for AvailabilityImpactType {
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

impl Display for ConfidentialityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for ConfidentialityImpactType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::C);

  fn help(&self) -> Help {
    match self {
      Self::High => {Help{ worth: Worth::Worst, des: "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.".to_string() }}
      Self::Low => {Help{ worth: Worth::Bad, des: "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no loss of confidentiality within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.0,
      Self::Low => 0.22,
      Self::High => 0.56,
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

impl Display for IntegrityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for IntegrityImpactType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::I);

  fn help(&self) -> Help {
    match self {
      Self::High => {Help{ worth: Worth::Worst, des: "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.".to_string() }}
      Self::Low => {Help{ worth: Worth::Bad, des: "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no loss of integrity within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.0,
      Self::Low => 0.22,
      Self::High => 0.56,
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

impl Display for AvailabilityImpactType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for AvailabilityImpactType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::A);

  fn help(&self) -> Help {
    match self {
      Self::High => { Help { worth: Worth::Worst, des: "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly knowledge_base a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).".to_string() } }
      Self::Low => {Help{ worth: Worth::Bad, des: "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.".to_string() }}
      Self::None => {Help{ worth: Worth::Good, des: "There is no impact to availability within the impacted component.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::None => 0.0,
      Self::Low => 0.22,
      Self::High => 0.56,
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

impl ConfidentialityImpactType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}

impl IntegrityImpactType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl AvailabilityImpactType {
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
pub struct Impact {
  /// [`ConfidentialityImpactType`] 机密性影响（C）
  pub confidentiality_impact: ConfidentialityImpactType,
  /// [`IntegrityImpactType`] 完整性影响（I）
  pub integrity_impact: IntegrityImpactType,
  /// [`AvailabilityImpactType`] 可用性影响（A）
  pub availability_impact: AvailabilityImpactType,
}

impl Impact {
  /// 𝐼𝑆𝐶𝐵𝑎𝑠𝑒 = 1 − [(1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐶𝑜𝑛𝑓) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐼𝑛𝑡𝑒𝑔) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐴𝑣𝑎𝑖𝑙)]
  pub(crate) fn impact_sub_score_base(&self) -> f32 {
    let c_score = self.confidentiality_impact.score();
    let i_score = self.integrity_impact.score();
    let a_score = self.availability_impact.score();
    1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score)).abs()
  }
}
