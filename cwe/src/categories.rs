//! A category is a collection of weaknesses based on some common characteristic or attribute.
//! The shared attribute may be any number of things including, but not limited to, environment
//! (J2EE, .NET), functional area (authentication, cryptography) and the relevant resource
//! (credentials management, certificate issues). A Category is used primarily as an organizational
//! mechanism for CWE and should not be mapped to by external sources.
//!
//! The required Summary element contains the key points that define the category and helps the user
//! understand what the category is attempting to be. The optional Relationships element is used to
//! define relationships (Member_Of and Has_Member) with other weaknesses, categories, and views.
//! The optional Taxonomy_Mappings element is used to relate this category to similar categories in
//! taxomomies outside of CWE. The optional References element is used to provide further reading
//! and insight into this category. This element should be used when the category is based on
//! external sources or projects. The optional Notes element is used to provide additional comments
//! or clarifications that cannot be captured using the other elements of the category. The optional
//! Content_History element is used to keep track of the original author of the category and any
//! subsequent modifications to the content. This provides a means of contacting the authors and
//! modifiers for clarifying ambiguities, or in merging overlapping contributions.
//!
//! The required ID attribute provides a unique identifier for the category. It is meant to be
//! static for the lifetime of the category. If the category becomes deprecated, the ID should not
//! be reused, and a placeholder for the deprecated category should be left in the catalog.
//! The required Name attribute provides a descriptive title used to give the reader an idea of
//! what characteristics this category represents. All words in the name should be capitalized
//! except for articles and prepositions unless they begin or end the name. The required Status
//! attribute defines the maturity of the information for this category. Please refer to the
//! StatusEnumeration simple type for a list of valid values and their meanings.
//!
use crate::content_history::ContentHistory;
use crate::mapping_notes::MappingNotes;
use crate::notes::Notes;
use crate::relationships::Relationships;
use crate::structured_text::StructuredText;
use crate::weaknesses::{References, TaxonomyMappings};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Categories {
  #[serde(rename(deserialize = "Category"), default)]
  pub categories: Vec<Category>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename(deserialize = "Category"))]
pub struct Category {
  #[serde(rename(deserialize = "@ID"))]
  pub id: i64,
  #[serde(rename(deserialize = "@Name"))]
  pub name: String,
  #[serde(rename(deserialize = "@Status"))]
  pub status: String,
  #[serde(rename(deserialize = "Summary"))]
  pub summary: StructuredText,
  #[serde(rename(deserialize = "Relationships"))]
  pub relationships: Option<Relationships>,
  #[serde(rename(deserialize = "References"))]
  pub references: Option<References>,
  #[serde(rename(deserialize = "Mapping_Notes"))]
  pub mapping_notes: MappingNotes,
  #[serde(rename(deserialize = "Notes"))]
  pub notes: Option<Notes>,
  #[serde(rename(deserialize = "Content_History"))]
  pub content_history: ContentHistory,
  #[serde(rename(deserialize = "Taxonomy_Mappings"))]
  pub taxonomy_mappings: Option<TaxonomyMappings>,
}
