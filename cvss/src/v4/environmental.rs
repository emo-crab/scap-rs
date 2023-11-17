use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct Environmental {
  /// [`ConfidentialityImpactType`] 机密性影响（C）
  pub confidentiality_requirements: ConfidentialityRequirements,
  /// [`IntegrityImpactType`] 完整性影响（I）
  pub integrity_requirements: IntegrityRequirements,
  /// [`AvailabilityImpactType`] 可用性影响（A）
  pub availability_requirements: AvailabilityRequirements,
}

impl Default for Environmental {
  fn default() -> Self {
    Environmental{
      confidentiality_requirements: ConfidentialityRequirements::NotDefined,
      integrity_requirements: IntegrityRequirements::NotDefined,
      availability_requirements: AvailabilityRequirements::NotDefined,
    }
  }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidentialityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [ConfidentialityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [ConfidentialityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [ConfidentialityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [IntegrityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [IntegrityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [IntegrityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AvailabilityRequirements {
  /// NotDefined(X) 这是默认值。分配此值表示没有足够的信息来选择其他值之一。这与将“高”指定为最坏情况的效果相同。
  NotDefined,
  /// High(H) [AvailabilityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生灾难性的不利影响。
  High,
  /// Medium(M) [AvailabilityRequirements]可能会对组织或与组织相关的个人（例如，员工、客户）产生严重的不利影响。
  Medium,
  /// Low(L) [AvailabilityRequirements]可能对组织或与组织相关的个人（例如，员工、客户）产生有限的不利影响。
  Low,
}
