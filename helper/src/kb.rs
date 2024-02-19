use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
  pub links: Links,
  pub data: Vec<Daum>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Links {
  pub next: Next,
  #[serde(rename = "self")]
  pub self_field: Self_field,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Next {
  pub href: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Self_field {
  pub href: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Daum {
  pub id: String,
  pub editor_id: String,
  pub name: String,
  pub created: String,
  pub revision_date: String,
  pub disclosure_date: Option<String>,
  pub document: String,
  pub metadata: Metadata,
  pub score: Score,
  #[serde(rename = "rapid7Analysis")]
  pub rapid7analysis: Option<String>,
  #[serde(rename = "rapid7AnalysisCreated")]
  pub rapid7analysis_created: Option<String>,
  #[serde(rename = "rapid7AnalysisRevisionDate")]
  pub rapid7analysis_revision_date: Option<String>,
  pub tags: Vec<Tag>,
  pub references: Vec<Reference>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
  pub vendor: Vendor,
  pub cve_state: String,
  pub cvss_metric_v31: Option<CvssMetricV31>,
  #[serde(default)]
  pub configurations: Vec<String>,
  #[serde(rename = "vulnerable-versions")]
  #[serde(default)]
  pub vulnerable_versions: Vec<String>,
  pub credits: Option<Credits>,
  pub userbase: Option<String>,
  pub stability: Option<String>,
  #[serde(rename = "shelf-life")]
  pub shelf_life: Option<String>,
  pub exploitable: Option<String>,
  pub mitigations: Option<String>,
  pub reliability: Option<String>,
  pub authenticated: Option<String>,
  #[serde(rename = "utility-class")]
  pub utility_class: Option<String>,
  #[serde(rename = "patch-effectiveness")]
  pub patch_effectiveness: Option<String>,
  #[serde(rename = "offensive-application")]
  pub offensive_application: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vendor {
  #[serde(default)]
  pub vendor_names: Vec<String>,
  #[serde(default)]
  pub product_names: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV31 {
  #[serde(rename = "type")]
  pub type_field: String,
  pub source: String,
  pub cvss_data: CvssData,
  pub impact_score: f64,
  pub exploitability_score: f64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
  pub scope: String,
  pub version: String,
  pub base_score: f64,
  pub attack_vector: String,
  pub base_severity: String,
  pub vector_string: String,
  pub integrity_impact: String,
  pub user_interaction: String,
  pub attack_complexity: String,
  pub availability_impact: String,
  pub privileges_required: String,
  pub confidentiality_impact: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credits {
  #[serde(rename = "discovered-by")]
  pub discovered_by: Vec<String>,
  #[serde(default)]
  pub reporter: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
  pub attacker_value: i64,
  pub exploitability: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
  pub id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
  pub id: String,
}
