use serde::{Deserialize, Serialize};
use crate::v2::LimitOffset;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CveHistoryParameters {
    cve_id: Option<String>,
    #[serde(flatten)]
    change_date: Option<ChangeDate>,
    event_name: Option<EventName>,
    #[serde(flatten)]
    limit_offset: Option<LimitOffset>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeDate {
    change_start_date: String,
    change_end_date: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EventName {
    #[serde(rename = "CVE Received")]
    CVEReceived,
    #[serde(rename = "Initial Analysis")]
    InitialAnalysis,
    Reanalysis,
    #[serde(rename = "CVE Modified")]
    CVEModified,
    #[serde(rename = "Modified Analysis")]
    ModifiedAnalysis,
    #[serde(rename = "CVE Translated")]
    CVETranslated,
    #[serde(rename = "Vendor Comment")]
    VendorComment,
    #[serde(rename = "CVE Source Update")]
    CVESourceUpdate,
    #[serde(rename = "CPE Deprecation Remap")]
    CPEDeprecationRemap,
    #[serde(rename = "CWE Remap")]
    CWERemap,
    #[serde(rename = "CVE Rejected")]
    CVERejected,
    #[serde(rename = "CVE Unrejected")]
    CVEUnRejected,
}