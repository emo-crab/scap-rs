use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReferences {
    #[serde(rename = "$value", default)]
    pub external_references: Vec<ExternalReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReference {
    #[serde(rename = "@Reference_ID")]
    pub reference_id: String,
    #[serde(rename = "Author", default)]
    pub author: Vec<String>,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Edition")]
    pub edition: Option<String>,
    #[serde(rename = "Publication")]
    pub publication: Option<String>,
    #[serde(rename = "Publication_Year")]
    pub publication_year: Option<String>,
    #[serde(rename = "Publication_Month")]
    pub publication_month: Option<String>,
    #[serde(rename = "Publication_Day")]
    pub publication_day: Option<String>,
    #[serde(rename = "Publisher")]
    pub publisher: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "URL_Date")]
    pub url_date: Option<String>,
}