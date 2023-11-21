//! ### Vulnerability Metrics
//! The Common Vulnerability Scoring System (CVSS) is a method used to supply a qualitative measure of severity. CVSS is not a measure of risk. CVSS consists of three metric groups: Base, Temporal, and Environmental. The Base metrics produce a score ranging from 0 to 10, which can then be modified by scoring the Temporal and Environmental metrics. A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score. Thus, CVSS is well suited as a standard measurement system for industries, organizations, and governments that need accurate and consistent vulnerability severity scores. Two common uses of CVSS are calculating the severity of vulnerabilities discovered on one's systems and as a factor in prioritization of vulnerability remediation activities. The National Vulnerability Database (NVD) provides CVSS scores for almost all known vulnerabilities.
//!
//! The NVD supports both Common Vulnerability Scoring System (CVSS) v2.0 and v3.X standards. The NVD provides CVSS 'base scores' which represent the innate characteristics of each vulnerability. The NVD does not currently provide 'temporal scores' (metrics that change over time due to events external to the vulnerability) or 'environmental scores' (scores customized to reflect the impact of the vulnerability on your organization). However, the NVD does supply a CVSS calculator for both CVSS v2 and v3 to allow you to add temporal and environmental score data.
//!
//! CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. The official CVSS documentation can be found at  <https://www.first.org/cvss/>.

#![doc(html_root_url = "https://emo-car.github.io/nvd-rs/cvss")]
// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json
// https://www.first.org/cvss/specification-document
pub mod error;
pub mod metric;
pub mod severity;
pub mod v2;
pub mod v3;
pub mod v4;
pub mod version;
/// Roundup保留小数点后一位，小数点后第二位大于零则进一。 例如, Roundup(4.02) = 4.1; 或者 Roundup(4.00) = 4.0
///
/// Where “Round up” is defined as the smallest number,
/// specified to one decimal place, that is equal to or higher than its input. For example,
/// Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
///
/// 1.  `function Roundup (input):`
/// 2.  `    int_input = round_to_nearest_integer (input * 100000)`
/// 3.  `    if (int_input % 10000) == 0:`
/// 4.  `        return int_input / 100000.0`
/// 5.  `    else:`
/// 6.  `        return (floor(int_input / 10000) + 1) / 10.0`
pub(crate) fn roundup(input: f32) -> f32 {
  let int_input = (input * 100_000.0) as u32;
  if int_input % 10000 == 0 {
    (int_input as f32) / 100_000.0
  } else {
    let score_floor = ((int_input as f32) / 10_000.0).floor();
    (score_floor + 1.0) / 10.0
  }
}
