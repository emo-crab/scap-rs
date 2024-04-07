// CNVD的反爬需要执行js设置cookie，而且有防火墙。所以选CNNVD的API
#![allow(clippy::large_enum_variant)]

use chrono::NaiveDate;
use derive_builder::Builder;
use reqwest::{ClientBuilder, RequestBuilder};
use serde::{Deserialize, Serialize};

use crate::error::Error;

const BASE_URL: &str = "https://www.cnnvd.org.cn/web/";

#[derive(Debug, Clone)]
pub struct CNNVDApi {
  base_path: String,
  client: reqwest::Client,
}

impl CNNVDApi {
  pub fn new() -> Result<Self, Error> {
    let api_client = ClientBuilder::new()
      .build()
      .map_err(|source| Error::BuildingClient { source })?;
    Ok(CNNVDApi {
      base_path: BASE_URL.to_owned(),
      client: api_client,
    })
  }
  async fn request(&self, request: RequestBuilder) -> Result<CNNVDResult, Error> {
    let request = request.build()?;
    let result = self
      .client
      .execute(request)
      .await
      .map_err(|source| Error::RequestFailed { source })?
      .json()
      .await
      .map_err(|source| Error::ResponseIo { source })?;
    // let result = serde_json::from_str(&json).unwrap();
    Ok(result)
  }
}

impl CNNVDApi {
  pub async fn detail(&self, query: DetailParameters) -> Result<CNNVDResult, Error> {
    let u = format!(
      "{}/{}",
      self.base_path, "cnnvdVul/getCnnnvdDetailOnDatasource"
    );
    self.request(self.client.post(u).json(&query)).await
  }
  pub async fn vul_list(&self, query: VulListParameters) -> Result<CNNVDResult, Error> {
    let u = format!("{}/{}", self.base_path, "homePage/cnnvdVulList");
    self.request(self.client.post(u).json(&query)).await
  }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, Builder)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
pub struct DetailParameters {
  pub id: Option<String>,
  pub vul_type: Option<String>,
  pub cnnvd_code: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, Builder)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
pub struct VulListParameters {
  pub begin_time: Option<NaiveDate>,
  pub end_time: Option<NaiveDate>,
  pub page_index: Option<i64>,
  pub page_size: Option<i64>,
  pub keyword: Option<String>,
  pub hazard_level: Option<String>,
  pub vul_type: Option<String>,
  pub vendor: Option<String>,
  pub product: Option<String>,
  pub date_type: Option<DataType>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataType {
  #[default]
  UpdateTime,
  PublishTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CNNVDResult {
  pub code: u16,
  pub success: bool,
  pub message: String,
  pub data: CNNVDData,
  pub time: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CNNVDData {
  Detail(Detail),
  VulList(VulList),
  None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
  pub cnnvd_detail: CNNVDDetail,
  pub recevice_vul_detail: Option<String>,
}

// 漏洞详情
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CNNVDDetail {
  pub id: Option<String>,
  pub vul_name: String,
  pub cnnvd_code: String,
  pub cve_code: Option<String>,
  pub publish_time: String,
  pub is_official: i64,
  pub vendor: Option<String>,
  pub hazard_level: Option<u16>,
  pub vul_type: Option<String>,
  pub vul_type_name: Option<String>,
  pub vul_desc: String,
  pub affected_product: Option<String>,
  pub affected_vendor: Option<String>,
  pub product_desc: Option<String>,
  pub affected_system: Option<String>,
  pub refer_url: Option<String>,
  pub patch_id: Option<String>,
  pub patch: Option<String>,
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

// 漏洞列表
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulList {
  pub total: i64,
  pub records: Vec<Record>,
  pub page_index: i64,
  pub page_size: i64,
}

// 单个记录
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

// 从列表的单个记录转为详情搜索参数
impl From<Record> for DetailParameters {
  fn from(val: Record) -> Self {
    DetailParameters {
      id: Some(val.id),
      vul_type: Some(val.vul_type),
      cnnvd_code: Some(val.cnnvd_code),
    }
  }
}
