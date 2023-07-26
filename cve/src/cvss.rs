// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json

pub mod v3 {
  // https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  use serde::{Deserialize, Serialize};
  // AV
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum AttackVectorType {
    // AV:N
    #[serde(rename = "NETWORK")]
    Network,
    // AV:A
    #[serde(rename = "ADJACENT_NETWORK")]
    AdjacentNetwork,
    // AV:L
    #[serde(rename = "LOCAL")]
    Local,
    // AV:P
    #[serde(rename = "PHYSICAL")]
    Physical,
  }
  // AC
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum AttackComplexityType {
    // AC:H
    #[serde(rename = "HIGH")]
    High,
    // AC:L
    #[serde(rename = "LOW")]
    Low,
  }
  // PR
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum PrivilegesRequiredType {
    // PR:H
    #[serde(rename = "HIGH")]
    High,
    // PR:L
    #[serde(rename = "LOW")]
    Low,
    // PR:N
    #[serde(rename = "NONE")]
    None,
  }
  // UI
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum UserInteractionType {
    // UI:R
    #[serde(rename = "REQUIRED")]
    Required,
    // UI:N
    #[serde(rename = "NONE")]
    None,
  }
  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum ImpactMetricsType {
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "NONE")]
    None,
  }
  // S
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum ScopeType {
    // S:U
    #[serde(rename = "UNCHANGED")]
    Unchanged,
    // S:C
    #[serde(rename = "CHANGED")]
    Changed,
  }
  // 严重性
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum SeverityType {
    // 未校正
    #[serde(rename = "NONE")]
    None,
    // 低危
    #[serde(rename = "LOW")]
    Low,
    // 中危
    #[serde(rename = "MEDIUM")]
    Medium,
    // 高危
    #[serde(rename = "HIGH")]
    High,
    // 严重
    #[serde(rename = "CRITICAL")]
    Critical,
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct CVSS {
    // 版本： 3.0 和 3.1
    pub version: String,
    // 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    // 访问途径（AV）
    #[serde(rename = "attackVector")]
    pub attack_vector: AttackVectorType,
    // 攻击复杂度（AC）
    #[serde(rename = "attackComplexity")]
    pub attack_complexity: AttackComplexityType,
    // 所需权限（PR）
    #[serde(rename = "privilegesRequired")]
    pub privileges_required: PrivilegesRequiredType,
    // 用户交互（UI）
    #[serde(rename = "userInteraction")]
    pub user_interaction: UserInteractionType,
    // 影响范围（S）
    pub scope: ScopeType,
    // 机密性影响（C）
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    // 基础评级
    #[serde(rename = "baseSeverity")]
    pub base_severity: SeverityType,
  }
}

pub mod v2 {
  // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
  use serde::{Deserialize, Serialize};
  // AV
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum AccessVectorType {
    // AV:N
    #[serde(rename = "NETWORK")]
    Network,
    // AV:A
    #[serde(rename = "ADJACENT_NETWORK")]
    AdjacentNetwork,
    // AV:L
    #[serde(rename = "LOCAL")]
    Local,
  }
  // AC
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum AccessComplexityType {
    // AC:H
    #[serde(rename = "HIGH")]
    High,
    // AC:M
    #[serde(rename = "MEDIUM")]
    Medium,
    // AC:L
    #[serde(rename = "LOW")]
    Low,
  }
  // Au
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum AuthenticationType {
    // Au:M
    #[serde(rename = "MULTIPLE")]
    Multiple,
    // Au:S
    #[serde(rename = "SINGLE")]
    Single,
    // Au:N
    #[serde(rename = "NONE")]
    None,
  }
  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  pub enum ImpactMetricsType {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "COMPLETE")]
    Complete,
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  pub struct CVSS {
    // 版本
    pub version: String,
    // 向量: CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    // 访问向量
    #[serde(rename = "accessVector")]
    pub access_vector: AccessVectorType,
    // 访问复杂性
    #[serde(rename = "accessComplexity")]
    pub access_complexity: AccessComplexityType,
    // 认证
    pub authentication: AuthenticationType,
    // 完整性影响（I）
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    #[serde(rename = "baseScore")]
    pub base_score: f64,
  }
}
