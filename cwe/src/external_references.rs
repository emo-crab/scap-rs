use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReferences {
  #[serde(rename(deserialize = "$value"), default)]
  pub external_references: Vec<ExternalReference>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReference {
  #[serde(rename(deserialize = "@Reference_ID"))]
  pub reference_id: String,
  #[serde(rename(deserialize = "Author"), default)]
  pub author: Vec<String>,
  #[serde(rename(deserialize = "Title"))]
  pub title: String,
  #[serde(rename(deserialize = "Edition"))]
  pub edition: Option<String>,
  #[serde(rename(deserialize = "Publication"))]
  pub publication: Option<String>,
  #[serde(rename(deserialize = "Publication_Year"))]
  pub publication_year: Option<String>,
  #[serde(rename(deserialize = "Publication_Month"))]
  pub publication_month: Option<String>,
  #[serde(rename(deserialize = "Publication_Day"))]
  pub publication_day: Option<String>,
  #[serde(rename(deserialize = "Publisher"))]
  pub publisher: Option<String>,
  #[serde(rename(deserialize = "URL"))]
  pub url: Option<String>,
  #[serde(rename(deserialize = "URL_Date"))]
  pub url_date: Option<String>,
}
