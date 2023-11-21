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

impl AccessVectorType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Metric for AccessVectorType {
  const TYPE: MetricType = MetricType::V2(MetricTypeV2::AV);

  fn help(&self) -> Help {
    match self {
      Self::Network => {Help{ worth: Worth::Worst, des: "A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed \"remotely exploitable\". An example of a network attack is an RPC buffer overflow.".to_string() }}
      Self::AdjacentNetwork => {Help{ worth: Worth::Worse, des: "A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.".to_string() }}
      Self::Local => {Help{ worth: Worth::Bad, des: "A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::Network => 1.0,
      Self::AdjacentNetwork => 0.646,
      Self::Local => 0.395,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::Network => "N",
      Self::AdjacentNetwork => "A",
      Self::Local => "L",
    }
  }
}
impl FromStr for AccessVectorType {
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
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,A,L".to_string(),
      }),
    }
  }
}
