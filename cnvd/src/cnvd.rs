use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Vulnerabilitys {
  #[serde(default)]
  pub vulnerability: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
  pub number: String,
  pub title: String,
  pub cves: Option<Cves>,
  pub serverity: String,
  pub products: Products,
  pub is_event: String,
  pub submit_time: NaiveDate,
  pub open_time: NaiveDate,
  pub discoverer_name: String,
  pub reference_link: String,
  pub formal_way: String,
  pub description: String,
  pub patch_name: Option<String>,
  pub patch_description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cves {
  pub cve: Cve,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
  pub cve_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Products {
  pub product: Vec<String>,
}
