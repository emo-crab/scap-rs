use crate::error::{NVDDBError, Result};
use crate::models::{Cvss2, Cvss3};
use crate::schema::{cvss2, cvss3};
use cve::impact::{ImpactMetricV2, ImpactMetricV3};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

#[derive(Debug, Insertable)]
#[diesel(table_name = cvss2)]
pub struct NewCvss2 {
  pub id: Vec<u8>,
  pub version: String,
  pub vector_string: String,
  pub access_vector: String,
  pub access_complexity: String,
  pub authentication: String,
  pub confidentiality_impact: String,
  pub integrity_impact: String,
  pub availability_impact: String,
  pub base_score: f32,
  pub exploitability_score: f32,
  pub impact_score: f32,
  pub severity: String,
  pub ac_insuf_info: Option<u8>,
  pub obtain_all_privilege: u8,
  pub obtain_user_privilege: u8,
  pub obtain_other_privilege: u8,
  pub user_interaction_required: Option<u8>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = cvss3)]
pub struct CreateCvss3 {
  pub id: Vec<u8>,
  pub version: String,
  pub vector_string: String,
  pub attack_vector: String,
  pub attack_complexity: String,
  pub privileges_required: String,
  pub user_interaction: String,
  pub scope: String,
  pub confidentiality_impact: String,
  pub integrity_impact: String,
  pub availability_impact: String,
  pub base_score: f32,
  pub base_severity: String,
  pub exploitability_score: f32,
  pub impact_score: f32,
}

impl Cvss3 {
  // 创建弱点枚举
  pub fn create(conn: &mut MysqlConnection, args: &CreateCvss3) -> Result<Self> {
    if let Err(err) = diesel::insert_into(cvss3::table).values(args).execute(conn) {
      // 重复了，说明已经存在CVSS3
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
        }
      }
    }
    Ok(
      // mysql 不支持 get_result，要再查一次得到插入结果
      cvss3::dsl::cvss3
        .filter(cvss3::vector_string.eq(&args.vector_string))
        .limit(1)
        .first::<Cvss3>(conn)?,
    )
  }
  pub fn create_from_impact(
    conn: &mut MysqlConnection,
    impact: Option<ImpactMetricV3>,
  ) -> Option<Vec<u8>> {
    match impact {
      None => return None,
      Some(imv3) => {
        let new = CreateCvss3 {
          id: uuid::Uuid::new_v4().as_bytes().to_vec(),
          version: imv3.cvss_v3.version.to_string(),
          vector_string: imv3.cvss_v3.vector_string,
          attack_vector: format!("{:?}", imv3.cvss_v3.exploit_ability.attack_vector),
          attack_complexity: format!("{:?}", imv3.cvss_v3.exploit_ability.attack_complexity),
          privileges_required: format!("{:?}", imv3.cvss_v3.exploit_ability.privileges_required),
          user_interaction: format!("{:?}", imv3.cvss_v3.exploit_ability.user_interaction),
          scope: format!("{:?}", imv3.cvss_v3.scope),
          confidentiality_impact: format!("{:?}", imv3.cvss_v3.impact.confidentiality_impact),
          integrity_impact: format!("{:?}", imv3.cvss_v3.impact.integrity_impact),
          availability_impact: format!("{:?}", imv3.cvss_v3.impact.availability_impact),
          base_score: imv3.cvss_v3.base_score,
          base_severity: format!("{:?}", imv3.cvss_v3.base_severity),
          exploitability_score: imv3.exploitability_score,
          impact_score: imv3.impact_score,
        };
        if let Ok(c) = Self::create(conn, &new) {
          return Some(c.id);
        }
      }
    }
    None
  }
}

impl Cvss2 {
  // 创建弱点枚举
  pub fn create(conn: &mut MysqlConnection, args: &NewCvss2) -> Result<Self> {
    if let Err(err) = diesel::insert_into(cvss2::table).values(args).execute(conn) {
      // 重复了，说明已经存在CVSS2
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
        }
      }
    }
    Ok(
      // mysql 不支持 get_result，要再查一次得到插入结果
      cvss2::dsl::cvss2
        .filter(cvss2::vector_string.eq(&args.vector_string))
        .limit(1)
        .first::<Cvss2>(conn)?,
    )
  }
  pub fn create_from_impact(
    conn: &mut MysqlConnection,
    impact: Option<ImpactMetricV2>,
  ) -> Option<Vec<u8>> {
    match impact {
      None => return None,
      Some(imv2) => {
        let new = NewCvss2 {
          id: uuid::Uuid::new_v4().as_bytes().to_vec(),
          version: imv2.cvss_v2.version.to_string(),
          vector_string: imv2.cvss_v2.vector_string,
          access_vector: imv2.cvss_v2.access_vector.to_string(),
          access_complexity: imv2.cvss_v2.access_complexity.to_string(),
          authentication: imv2.cvss_v2.authentication.to_string(),
          confidentiality_impact: imv2.cvss_v2.confidentiality_impact.to_string(),
          integrity_impact: imv2.cvss_v2.integrity_impact.to_string(),
          availability_impact: imv2.cvss_v2.availability_impact.to_string(),
          base_score: imv2.cvss_v2.base_score,
          exploitability_score: imv2.exploitability_score,
          impact_score: imv2.impact_score,
          severity: imv2.severity,
          ac_insuf_info: imv2.ac_insuf_info.map(u8::from),
          obtain_all_privilege: u8::from(imv2.obtain_all_privilege),
          obtain_user_privilege: u8::from(imv2.obtain_other_privilege),
          obtain_other_privilege: u8::from(imv2.obtain_other_privilege),
          user_interaction_required: imv2.user_interaction_required.map(u8::from),
        };
        if let Ok(c) = Self::create(conn, &new) {
          return Some(c.id);
        }
      }
    }
    None
  }
}
