//! 7.4. Metric Values
//!
//! Each metric value has an associated constant which is used in the formulas, as defined in Table 16.
//!
//! **Table 16: Metric values**
//!
//!
//! | Metric | Metric Value | Numerical Value |
//! | --- | --- | --- |
//! | Attack Vector / Modified Attack Vector | Network | 0.85 |
//! |  | Adjacent | 0.62 |
//! |  | Local | 0.55 |
//! |  | Physical | 0.2 |
//! | Attack Complexity / Modified Attack Complexity | Low | 0.77 |
//! |  | High | 0.44 |
//! | Privileges Required / Modified Privileges Required | None | 0.85 |
//! |  | Low | 0.62 (or 0.68 if Scope / Modified Scope is Changed) |
//! |  | High | 0.27 (or 0.5 if Scope / Modified Scope is Changed) |
//! | User Interaction / Modified User Interaction | None | 0.85 |
//! |  | Required | 0.62 |
//! | Confidentiality / Integrity / Availability / Modified Confidentiality / Modified Integrity / Modified Availability | High | 0.56 |
//! |  | Low | 0.22 |
//! |  | None | 0 |
//! | Exploit Code Maturity | Not Defined | 1 |
//! |  | High | 1 |
//! |  | Functional | 0.97 |
//! |  | Proof of Concept | 0.94 |
//! |  | Unproven | 0.91 |
//! | Remediation Level | Not Defined | 1 |
//! |  | Unavailable | 1 |
//! |  | Workaround | 0.97 |
//! |  | Temporary Fix | 0.96 |
//! |  | Official Fix | 0.95 |
//! | Report Confidence | Not Defined | 1 |
//! |  | Confirmed | 1 |
//! |  | Reasonable | 0.96 |
//! |  | Unknown | 0.92 |
//! | Confidentiality Requirement / Integrity Requirement / Availability Requirement | Not Defined | 1 |
//! |  | High | 1.5 |
//! |  | Medium | 1 |
//! |  | Low | 0.5 |[](#body)
//!
use std::fmt::{Debug, Display};
use std::str::FromStr;

pub trait Metric: Clone + Debug + FromStr + Display {
  const NAME: &'static str;
  fn score(&self) -> f32;
  fn as_str(&self) -> &'static str;
}
