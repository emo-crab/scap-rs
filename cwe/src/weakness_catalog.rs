//! The Weakness_Catalog root element is used to describe a collection of security issues known as weaknesses
//! (e.g., flaws, faults, bugs). Each catalog can be organized by optional Views and Categories.
//! The catalog also contains a list of all External_References that may be shared throughout the
//! individual weaknesses. The required Name and Version attributes are used to uniquely identify
//! the catalog. The required Date attribute identifies the date when this catalog was created or last updated.
// https://github.com/serde-rs/serde/pull/1043/files
use crate::categories::Categories;
use crate::external_references::ExternalReferences;
use crate::views::Views;
use crate::weaknesses::Weaknesses;
use serde::{Deserialize, Serialize};
/// Weakness_Catalog
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename(deserialize = "Weakness_Catalog"))]
pub struct WeaknessCatalog {
  #[serde(rename(deserialize = "@Name"))]
  pub name: String,
  #[serde(rename(deserialize = "@Version"))]
  pub version: String,
  #[serde(rename(deserialize = "@Date"))]
  pub date: String,
  #[serde(rename(deserialize = "Weaknesses"))]
  pub weaknesses: Weaknesses,
  #[serde(rename(deserialize = "Categories"))]
  pub categories: Option<Categories>,
  #[serde(rename(deserialize = "Views"))]
  pub views: Views,
  #[serde(rename(deserialize = "External_References"))]
  pub external_references: ExternalReferences,
}
