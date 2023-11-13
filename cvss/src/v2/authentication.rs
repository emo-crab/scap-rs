//! ### 2.1.3. Authentication (Au)
//!
//! This metric measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. This metric does not gauge the strength or complexity of the authentication process, only that an attacker is required to provide credentials before an exploit may occur.  The possible values for this metric are listed in Table 3. The fewer authentication instances that are required, the higher the vulnerability score.
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | Multiple (M) | Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system. |
//! | Single (S) | The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface). |
//! | None (N) | Authentication is not required to exploit the vulnerability. |
//!
//! The metric should be applied based on the authentication the attacker requires before launching an attack.  For example, if a mail server is vulnerable to a command that can be issued before a user authenticates, the metric should be scored as "None" because the attacker can launch the exploit before credentials are required.  If the vulnerable command is only available after successful authentication, then the vulnerability should be scored as "Single" or "Multiple," depending on how many instances of authentication must occur before issuing the command.
//!

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV2, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Authentication
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuthenticationType {
  /// requires multiple instances of authentication: 0.45
  Multiple,
  /// requires single instance of authentication: 0.56
  Single,
  /// requires no authentication: 0.704
  None,
}

impl Display for AuthenticationType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl AuthenticationType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Metric for AuthenticationType {
  const TYPE: MetricType = MetricType::V2(MetricTypeV2::Au);

  fn help(&self) -> Help {
    match self {
      AuthenticationType::Multiple => Help {
        worth: Worth::Bad,
        des: "Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. An example is an attacker authenticating to an operating system in addition to providing credentials to access an application hosted on that system.".to_string(),
      },
      AuthenticationType::Single => Help {
        worth: Worth::Worse,
        des: "The vulnerability requires an attacker to be logged into the system (such as at a command line or via a desktop session or web interface).".to_string(),
      },
      AuthenticationType::None => Help {
        worth: Worth::Worst,
        des: "Authentication is not required to exploit the vulnerability.".to_string(),
      },
    }
  }

  fn score(&self) -> f32 {
    match self {
      AuthenticationType::Multiple => 0.45,
      AuthenticationType::Single => 0.56,
      AuthenticationType::None => 0.704,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AuthenticationType::Multiple => "M",
      AuthenticationType::Single => "S",
      AuthenticationType::None => "N",
    }
  }
}
impl FromStr for AuthenticationType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_string();
    if s.starts_with(Self::name()) {
      s = s
        .strip_prefix(&format!("{}:", Self::name()))
        .unwrap_or_default()
        .to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS { value: s })?
    };
    match c {
      'M' => Ok(Self::Multiple),
      'S' => Ok(Self::Single),
      'N' => Ok(Self::None),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
      }),
    }
  }
}
