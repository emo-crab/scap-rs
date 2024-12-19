//! ### 2.1.1. Attack Vector (AV)
//!
//! This metric reflects the context by which vulnerability exploitation is possible. This metric value (and consequently the Base Score) will be larger the more remote (logically, and physically) an attacker can be in order to knowledge_base the vulnerable component. The assumption is that the number of potential attackers for a vulnerability that could be exploited from across a network is larger than the number of potential attackers that could knowledge_base a vulnerability requiring physical access to a device, and therefore warrants a greater Base Score. The list of possible values is presented in Table 1.
//!
//! **Table 1: Attack Vector**
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | Network (N) | The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable _at the protocol level_ one or more network hops away (e.g., across one or more routers). An example of a network attack is an attacker causing a denial of service (DoS) by sending a specially crafted TCP packet across a wide area network (e.g., CVE‑2004‑0230). |
//! | Adjacent (A) | The vulnerable component is bound to the network stack, but the attack is limited _at the protocol level_ to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment (e.g., CVE‑2013‑6014). |
//! | Local (L) | The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <br>*   the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); _or_<br>*   the attacker relies on User Interaction by another person to perform actions required to knowledge_base the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).|
//! | Physical (P) | The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack\[^1\]) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA). |
//!
//! _Scoring Guidance_: When deciding between Network and Adjacent, if an attack can be launched over a wide area network or from outside the logically adjacent administrative network domain, use Network. Network should be used even if the attacker is required to be on the same intranet to knowledge_base the vulnerable system (e.g., the attacker can only knowledge_base the vulnerability from inside a corporate network).
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV3, Worth};

/// Attack Vector(AV) 攻击途径
///
/// > 该指标反映了攻击脆弱组件的环境可能。该度量值（以及相应的基本分数）将越大，
/// > 攻击者攻击脆弱组件的距离（逻辑上和物理上）就越远。
///
/// > This metric reflects the context by which vulnerability exploitation is possible.
/// > This metric value (and consequently the Base score) will be larger the more remote (logically,
/// > and physically) an attacker can be in order to knowledge_base the vulnerable component.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVectorType {
  /// Network(N) 远程网络
  ///
  /// 可远程利用，即此脆弱组件可被一个以上网络跃点的距离进行攻击（例如，跨路由器的第3层边界）。
  Network,
  /// Adjacent Network(A) 相邻网络
  ///
  /// 攻击仅限于同一共享物理（如蓝牙、IEEE 802.11）或逻辑（如本地IP子网）网络，并且不能跨OSI第3层边界（如路由器）执行。
  AdjacentNetwork,
  /// Local(L) 本地
  ///
  /// 攻击者只能通过本地读/写/执行功能进行攻击。在某些情况下，攻击者可能在本地登录以攻击脆弱组件，或者可能依赖用户交互来执行恶意文件。
  Local,
  /// Physical(P) 物理
  ///
  /// 攻击者只能通过物理方式接触或操作脆弱组件，例如将外围设备连接到系统。
  Physical,
}

impl Display for AttackVectorType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl AttackVectorType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Metric for AttackVectorType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::AV);

  fn help(&self) -> Help {
    match self {
      AttackVectorType::Network => {Help{ worth: Worth::Worst, des: "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers).".to_string() }}
      AttackVectorType::AdjacentNetwork => {Help{ worth: Worth::Worse, des: "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment.".to_string() }}
      AttackVectorType::Local => {Help{ worth: Worth::Bad, des: "The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: ".to_string() }}
      AttackVectorType::Physical => {Help{ worth: Worth::Good, des: "The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA).".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      AttackVectorType::Network => 0.85,
      AttackVectorType::AdjacentNetwork => 0.62,
      AttackVectorType::Local => 0.55,
      AttackVectorType::Physical => 0.2,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AttackVectorType::Physical => "P",
      AttackVectorType::Local => "L",
      AttackVectorType::AdjacentNetwork => "A",
      AttackVectorType::Network => "N",
    }
  }
}
impl FromStr for AttackVectorType {
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
      Some('N') => Ok(Self::Network),
      Some('A') => Ok(Self::AdjacentNetwork),
      Some('L') => Ok(Self::Local),
      Some('P') => Ok(Self::Physical),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,A,L,P".to_string(),
      }),
    }
  }
}
