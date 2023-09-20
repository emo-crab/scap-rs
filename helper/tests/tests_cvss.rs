#[cfg(test)]
mod tests {
  use cvss::severity::SeverityTypeV3;
  use cvss::v3::attack_complexity::AttackComplexityType;
  use cvss::v3::attack_vector::AttackVectorType;
  use cvss::v3::impact_metrics::{
    AvailabilityImpactType, ConfidentialityImpactType, IntegrityImpactType,
  };
  use cvss::v3::privileges_required::PrivilegesRequiredType;
  use cvss::v3::scope::ScopeType;
  use cvss::v3::user_interaction::UserInteractionType;
  use cvss::v3::{ExploitAbility, Impact};
  use cvss::version::Version;
  use std::collections::HashMap;
  use std::str::FromStr;

  #[test]
  fn it_works() {
    let result = 2 + 2;
    let cvss3 = cvss::v3::CVSS::from_str("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
    println!("{cvss3:?}");
    let cvss2 = cvss::v2::CVSS::from_str("CVSS:2.0/AV:L/AC:M/Au:N/C:C/I:C/A:C");
    println!("{cvss2:?}");
    assert_eq!(result, 4);
  }
  #[test]
  fn test_cvss() {
    let cvss3 = cvss::v3::CVSS::from_str("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H").unwrap();
    assert_eq!(
      cvss3.to_string(),
      "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    )
  }
  #[test]
  fn test_cvss_builder() {
    let cvss_builder = cvss::v3::CVSSBuilder::new(
      Version::V3_1,
      ExploitAbility {
        attack_vector: AttackVectorType::Network,
        attack_complexity: AttackComplexityType::Low,
        privileges_required: PrivilegesRequiredType::None,
        user_interaction: UserInteractionType::None,
      },
      ScopeType::Changed,
      Impact {
        confidentiality_impact: ConfidentialityImpactType::High,
        integrity_impact: IntegrityImpactType::High,
        availability_impact: AvailabilityImpactType::High,
      },
    );
    let cvss_v3 = cvss_builder.build();
    assert_eq!(
      cvss_v3.vector_string,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    );
    assert_eq!(cvss_v3.base_score, 10.0);
    assert_eq!(cvss_v3.base_severity, SeverityTypeV3::Critical);
  }
  #[test]
  fn test_cvss_scope() {
    let cvss_v3_unchanged =
      cvss::v3::CVSS::from_str("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H").unwrap();
    println!("{cvss_v3_unchanged:?}");
    assert_eq!(cvss_v3_unchanged.base_score, 7.1);
    assert_eq!(cvss_v3_unchanged.base_severity, SeverityTypeV3::High);
    let cvss_v3_changed =
      cvss::v3::CVSS::from_str("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:H").unwrap();
    assert_eq!(cvss_v3_changed.base_score, 8.2);
    assert_eq!(cvss_v3_changed.base_severity, SeverityTypeV3::High);
  }

  #[test]
  fn test_cvss_score() {
    let cvss_map: HashMap<&str, f32> = HashMap::from_iter([
      ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H", 5.5),
      ("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:N/I:L/A:N", 2.3),
      ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N", 4.5),
      ("CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:H", 7.0),
      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", 9.4),
      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
      ("CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.8),
    ]);
    for (c, s) in cvss_map.into_iter() {
      let cvss_v3 = cvss::v3::CVSS::from_str(c).unwrap();
      assert_eq!(cvss_v3.base_score, s);
    }
  }
}
