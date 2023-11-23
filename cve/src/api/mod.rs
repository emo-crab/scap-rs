use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use crate::{date_format, DescriptionData};
use crate::impact::ImpactMetrics;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
pub struct CVE {
    pub id: String,
    pub source_identifier: String,
    #[serde(with = "date_format")]
    pub published_date: NaiveDateTime,
    // 最后修改时间
    #[serde(with = "date_format")]
    pub last_modified_date: NaiveDateTime,
    pub vuln_status: VulnStatus,
    pub descriptions: Vec<DescriptionData>,
    pub metrics: ImpactMetrics,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VulnStatus {
    Analyzed
}