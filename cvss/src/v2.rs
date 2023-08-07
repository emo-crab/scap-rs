pub mod access_complexity;
pub mod access_vector;
pub mod authentication;
pub mod impact_metrics;

// https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
use crate::v2::access_complexity::AccessComplexityType;
use crate::v2::access_vector::AccessVectorType;
use crate::v2::authentication::AuthenticationType;
use crate::v2::impact_metrics::ImpactMetricsType;
use crate::version::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CVSS {
  // 版本
  pub version: Version,
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
