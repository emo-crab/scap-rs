// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json

pub mod v3 {
  // https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  use serde::{Deserialize, Serialize};
  // AV
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
  pub enum AttackVectorType {
    // AV:N
    Network,
    // AV:A
    AdjacentNetwork,
    // AV:L
    Local,
    // AV:P
    Physical,
  }
  // AC
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum AttackComplexityType {
    // AC:H
    High,
    // AC:L
    Low,
  }
  // PR
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum PrivilegesRequiredType {
    // PR:H
    High,
    // PR:L
    Low,
    // PR:N
    None,
  }
  // UI
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum UserInteractionType {
    // UI:R
    Required,
    // UI:N
    None,
  }
  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ImpactMetricsType {
    High,
    Low,
    None,
  }
  // S
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ScopeType {
    // S:U
    Unchanged,
    // S:C
    Changed,
  }
  // 严重性
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum SeverityType {
    // 未校正
    None,
    // 低危
    Low,
    // 中危
    Medium,
    // 高危
    High,
    // 严重
    Critical,
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct CVSS {
    // 版本： 3.0 和 3.1
    pub version: String,
    // 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    pub vector_string: String,
    // 访问途径（AV）
    pub attack_vector: AttackVectorType,
    // 攻击复杂度（AC）
    pub attack_complexity: AttackComplexityType,
    // 所需权限（PR）
    pub privileges_required: PrivilegesRequiredType,
    // 用户交互（UI）
    pub user_interaction: UserInteractionType,
    // 影响范围（S）
    pub scope: ScopeType,
    // 机密性影响（C）
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    pub base_score: f64,
    // 基础评级
    pub base_severity: SeverityType,
  }
}

pub mod v2 {
  // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
  use serde::{Deserialize, Serialize};
  // AV
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
  pub enum AccessVectorType {
    // AV:N
    Network,
    // AV:A
    AdjacentNetwork,
    // AV:L
    Local,
  }
  // AC
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum AccessComplexityType {
    // AC:H
    High,
    // AC:M
    Medium,
    // AC:L
    Low,
  }
  // Au
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum AuthenticationType {
    // Au:M
    Multiple,
    // Au:S
    Single,
    // Au:N
    None,
  }
  // CIA 影响指标 原json schema为ciaType
  #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
  #[serde(rename_all = "UPPERCASE")]
  pub enum ImpactMetricsType {
    None,
    Partial,
    Complete,
  }
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct CVSS {
    // 版本
    pub version: String,
    // 向量: CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C
    pub vector_string: String,
    // 访问向量
    pub access_vector: AccessVectorType,
    // 访问复杂性
    pub access_complexity: AccessComplexityType,
    // 认证
    pub authentication: AuthenticationType,
    // 完整性影响（I）
    pub confidentiality_impact: ImpactMetricsType,
    // 完整性影响（I）
    pub integrity_impact: ImpactMetricsType,
    // 可用性影响（A）
    pub availability_impact: ImpactMetricsType,
    // 基础评分
    pub base_score: f64,
  }
}
