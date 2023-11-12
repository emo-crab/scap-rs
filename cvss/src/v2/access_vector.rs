//! ### 2.1.1. Access Vector (AV)
//!
//! This metric reflects how the vulnerability is exploited. The possible values for this metric are listed in Table 1. The more remote an attacker can be to attack a host, the greater the vulnerability score.
//!
//! **Metric Value Description**
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | Local (L) | A vulnerability exploitable with only _local access_ requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo). |
//! | Adjacent Network (A) | A vulnerability exploitable with _adjacent network access_ requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment. |
//! | Network (N) | A vulnerability exploitable with _network access_ means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". An example of a network attack is an RPC buffer overflow. |
//!
//!

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV2, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// AccessVector
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessVectorType {
  /// network accessible: 1.0
  Network,
  /// adjacent network accessible: 0.646
  AdjacentNetwork,
  /// requires local access: 0.395
  Local,
}

impl Display for AccessVectorType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for AccessVectorType {
  const TYPE: MetricType = MetricType::V2(MetricTypeV2::AV);

  fn help(&self) -> Help {
    match self {
      AccessVectorType::Network => {Help{ worth: Worth::Worst, des: " The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers).".to_string() }}
      AccessVectorType::AdjacentNetwork => {Help{ worth: Worth::Worse, des: " The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment.".to_string() }}
      AccessVectorType::Local => {Help{ worth: Worth::Bad, des: " The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: ".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      AccessVectorType::Network => 1.0,
      AccessVectorType::AdjacentNetwork => 0.646,
      AccessVectorType::Local => 0.395,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AccessVectorType::Network => "N",
      AccessVectorType::AdjacentNetwork => "A",
      AccessVectorType::Local => "L",
    }
  }
}
impl FromStr for AccessVectorType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with(Self::name()) {
      s = s
        .strip_prefix(&format!("{}:", Self::name()))
        .unwrap_or_default()
        .to_string();
    }
    let c = {
      let c = s.chars().next();
      c.ok_or(CVSSError::InvalidCVSS { value: s })?
    };
    match c {
      'N' => Ok(Self::Network),
      'A' => Ok(Self::AdjacentNetwork),
      'L' => Ok(Self::Local),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
      }),
    }
  }
}
