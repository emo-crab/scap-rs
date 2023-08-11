use serde::{Deserialize, Serialize};
use crate::external_references::ExternalReferences;
use crate::weaknesses::Weaknesses;
// https://github.com/serde-rs/serde/pull/1043/files
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WeaknessCatalog {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
    // #[serde(rename = "Weaknesses")]
    // pub weaknesses: Weaknesses,
    // #[serde(rename = "Categories")]
    // pub categories: Option<Categories>,
    // #[serde(rename = "Views")]
    // pub views: Option<Views>,
    // #[serde(rename = "External_References")]
    pub external_references: Option<ExternalReferences>,
}