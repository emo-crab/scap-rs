use serde::{Deserialize, Serialize};
// 通用漏洞评分系统

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CVSSV2 {
  // 版本
  pub version: String,
  // 向量: CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C
  #[serde(rename = "vectorString")]
  pub vector_string: String,
  // 访问向量
  #[serde(rename = "accessVector")]
  pub access_vector: String,
  // 访问复杂性
  #[serde(rename = "accessComplexity")]
  pub access_complexity: String,
  // 认证
  pub authentication: String,
  // 完整性影响（I）
  #[serde(rename = "confidentialityImpact")]
  pub confidentiality_impact: String,
  // 完整性影响（I）
  #[serde(rename = "integrityImpact")]
  pub integrity_impact: String,
  // 可用性影响（A）
  #[serde(rename = "availabilityImpact")]
  pub availability_impact: String,
  // 基础评分
  #[serde(rename = "baseScore")]
  pub base_score: f64,
}

// https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CVSSV3 {
  // 版本： 3.0 和 3.1
  pub version: String,
  // 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  #[serde(rename = "vectorString")]
  pub vector_string: String,
  // 访问途径（AV）
  #[serde(rename = "attackVector")]
  pub attack_vector: String,
  // 攻击复杂度（AC）
  #[serde(rename = "attackComplexity")]
  pub attack_complexity: String,
  // 所需权限（PR）
  #[serde(rename = "privilegesRequired")]
  pub privileges_required: String,
  // 用户交互（UI）
  #[serde(rename = "userInteraction")]
  pub user_interaction: String,
  // 影响范围（S）
  pub scope: String,
  // 机密性影响（C）
  #[serde(rename = "confidentialityImpact")]
  pub confidentiality_impact: String,
  // 完整性影响（I）
  #[serde(rename = "integrityImpact")]
  pub integrity_impact: String,
  // 可用性影响（A）
  #[serde(rename = "availabilityImpact")]
  pub availability_impact: String,
  // 基础评分
  #[serde(rename = "baseScore")]
  pub base_score: f64,
  // 基础评级
  #[serde(rename = "baseSeverity")]
  pub base_severity: String,
}
