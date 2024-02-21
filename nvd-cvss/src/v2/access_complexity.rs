//! ### 2.1.2. Access Complexity (AC)
//!
//! This metric measures the complexity of the attack required to knowledge_base the vulnerability once an attacker has gained access to the target system. For example, consider a buffer overflow in an Internet service: once the target system is located, the attacker can launch an knowledge_base at will.
//!
//! Other vulnerabilities, however, may require additional steps in order to be exploited. For example, a vulnerability in an email client is only exploited after the user downloads and opens a tainted attachment. The possible values for this metric are listed in Table 2. The lower the required complexity, the higher the vulnerability score.
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | High (H) | Specialized access conditions exist. For example:
//! ||\- In most configurations, the attacking party must already have elevated privileges or spoof additional systems in addition to the attacking system (e.g., DNS hijacking).
//! ||\- The attack depends on social engineering methods that would be easily detected by knowledgeable people. For example, the victim must perform several suspicious or atypical actions.
//! ||\- The vulnerable configuration is seen very rarely in practice.
//! ||\- If a race condition exists, the window is very narrow. |
//! | Medium (M) | The access conditions are somewhat specialized; the following are examples:
//! ||\- The attacking party is limited to a group of systems or users at some level of authorization, possibly untrusted.
//! ||\- Some information must be gathered before a successful attack can be launched.
//! ||\- The affected configuration is non-default, and is not commonly configured (e.g., a vulnerability present when a server performs user account authentication via a specific scheme, but not present for another authentication scheme).
//! ||\- The attack requires a small amount of social engineering that might occasionally fool cautious users (e.g., phishing attacks that modify a web browsers status bar to show a false link, having to be on someones buddy list before sending an IM knowledge_base). |
//! | Low (L) | Specialized access conditions or extenuating circumstances do not exist. The following are examples:
//! ||\- The affected product typically requires access to a wide range of systems and users, possibly anonymous and untrusted (e.g., Internet-facing web or mail server).
//! ||\- The affected configuration is default or ubiquitous.
//! ||\- The attack can be performed manually and requires little skill or additional information gathering.
//! ||\- The race condition is a lazy one (i.e., it is technically a race but easily winnable). |
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV2, Worth};

/// AccessComplexity
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccessComplexityType {
  /// high: 0.35
  High,
  /// medium: 0.61
  Medium,
  /// low: 0.71
  Low,
}
impl Display for AccessComplexityType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl AccessComplexityType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Metric for AccessComplexityType {
  const TYPE: MetricType = MetricType::V2(MetricTypeV2::AC);

  fn help(&self) -> Help {
    match self {
      Self::High => Help {
        worth: Worth::Bad,
        des: "In most configurations, the attacking party must already have elevated privileges or spoof additional systems in addition to the attacking system (e.g., DNS hijacking).".to_string(),
      },
      Self::Medium => Help {
        worth: Worth::Worse,
        des: "The attacking party is limited to a group of systems or users at some level of authorization, possibly untrusted.".to_string(),
      },
      Self::Low => Help {
        worth: Worth::Worst,
        des: "The affected product typically requires access to a wide range of systems and users, possibly anonymous and untrusted (e.g., Internet-facing web or mail server).".to_string(),
      },
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::High => 0.35,
      Self::Medium => 0.61,
      Self::Low => 0.71,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::High => "H",
      Self::Medium => "M",
      Self::Low => "L",
    }
  }
}
impl FromStr for AccessComplexityType {
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
      Some('H') => Ok(Self::High),
      Some('M') => Ok(Self::Medium),
      Some('L') => Ok(Self::Low),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "H,M,L".to_string(),
      }),
    }
  }
}
