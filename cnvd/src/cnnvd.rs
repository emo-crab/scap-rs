// CNVD的反爬需要执行js设置cookie，而且有防火墙。所以选CNNVD的API
#![allow(clippy::large_enum_variant)]

use serde::{Deserialize, Serialize};

const BASE_URL: &str = "https://www.cnnvd.org.cn/web/";

#[derive(Debug, Clone)]
pub struct CNNVDApi {
  base_path: String,
  client: reqwest::Client,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CNNVD {
  code: u16,
  success: bool,
  message: String,
  data: Data,
  time: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Data {
  Detail(Detail),
  VulList(VulList),
  None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
  pub cnnvd_detail: CnnvdDetail,
  pub recevice_vul_detail: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CnnvdDetail {
  pub id: Option<String>,
  pub vul_name: String,
  pub cnnvd_code: String,
  pub cve_code: String,
  pub publish_time: String,
  pub is_official: i64,
  pub vendor: String,
  pub hazard_level: Option<String>,
  pub vul_type: String,
  pub vul_type_name: String,
  pub vul_desc: String,
  pub affected_product: Option<String>,
  pub affected_vendor: String,
  pub product_desc: Option<String>,
  pub affected_system: Option<String>,
  pub refer_url: String,
  pub patch_id: Option<String>,
  pub patch: String,
  pub deleted: Option<String>,
  pub version: Option<String>,
  pub create_uid: Option<String>,
  pub create_uname: Option<String>,
  pub create_time: Option<String>,
  pub update_uid: Option<String>,
  pub update_uname: Option<String>,
  pub update_time: String,
  pub cnnvd_filed_show: String,
  pub cve_vul_vo: Option<String>,
  pub cve_filed_show: Option<String>,
  pub ibm_vul_vo: Option<String>,
  pub ibm_filed_show: Option<String>,
  pub ics_cert_vul_vo: Option<String>,
  pub ics_cert_filed_show: Option<String>,
  pub microsoft_vul_vo: Option<String>,
  pub microsoft_filed_show: Option<String>,
  pub huawei_vul_vo: Option<String>,
  pub huawei_filed_show: Option<String>,
  pub nvd_vul_vo: Option<String>,
  pub nvd_filed_show: Option<String>,
  pub varchar1: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulList {
  pub total: i64,
  pub records: Vec<Record>,
  pub page_index: i64,
  pub page_size: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
  pub id: String,
  pub vul_name: String,
  pub cnnvd_code: String,
  pub cve_code: String,
  pub hazard_level: i64,
  pub create_time: String,
  pub publish_time: String,
  pub update_time: String,
  pub type_name: Option<String>,
  pub vul_type: String,
}
