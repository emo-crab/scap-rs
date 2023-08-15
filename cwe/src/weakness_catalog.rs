//! The Weakness_Catalog root element is used to describe a collection of security issues known as weaknesses
//! (e.g., flaws, faults, bugs). Each catalog can be organized by optional Views and Categories.
//! The catalog also contains a list of all External_References that may be shared throughout the
//! individual weaknesses. The required Name and Version attributes are used to uniquely identify
//! the catalog. The required Date attribute identifies the date when this catalog was created or last updated.
// https://github.com/serde-rs/serde/pull/1043/files
use serde::{Deserialize, Serialize};
use crate::categories::Categories;
use crate::external_references::ExternalReferences;
use crate::views::Views;
use crate::weaknesses::Weaknesses;
/// Weakness_Catalog
#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness_Catalog")]
pub struct WeaknessCatalog {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
    #[serde(rename = "Weaknesses")]
    pub weaknesses: Weaknesses,
    #[serde(rename = "Categories")]
    pub categories: Option<Categories>,
    #[serde(rename = "Views")]
    pub views: Views,
    #[serde(rename = "External_References")]
    pub external_references: ExternalReferences,
}