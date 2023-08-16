//! A view represents a perspective with which one might look at the weaknesses in the catalog.
//! There are three different types of views as defined by the type attribute: graphs,
//! explicit slices, and implicit slices. The members of a view are either defined externally
//! through the members element (in the case of a graph or an explicit slice) or by the optional
//! filter element (in the case of an implicit slice).
//!
//! The required Objective element describes the perspective from which the view has been constructed.
//! The optional Audience element provides a reference to the target stakeholders or groups for
//! whom the view is most relevant. The optional Members element is used to define Member_Of
//! relationships with categories. The optional Filter element is only used for implicit slices
//! (see the Type attribute) and holds an XSL query for identifying which entries are members of
//! the view. The optional References element is used to provide further reading and insight into
//! this view. This element should be used when the view is based on external sources or projects.
//! The optional Notes element is used to provide any additional comments that cannot be captured
//! using the other elements of the view. The optional Content_History element is used to keep track
//! of the original author of the view and any subsequent modifications to the content.
//! This provides a means of contacting the authors and modifiers for clarifying ambiguities,
//! or in merging overlapping contributions.
//!
//! The required ID attribute provides a unique identifier for the view. It is meant to be static
//! for the lifetime of the view. If the view becomes deprecated, the ID should not be reused,
//! and a placeholder for the deprecated view should be left in the catalog. The required Name
//! attribute provides a descriptive title used to give the reader an idea of what perspective this
//! view represents. All words in the name should be capitalized except for articles and prepositions,
//! unless they begin or end the name. The required Type attribute describes how this view is being
//! constructed. Please refer to the ViewTypeEnumeration simple type for a list of valid values and
//! their meanings. The required Status attribute defines the maturity of the information for this
//! view. Please refer to the StatusEnumeration simple type for a list of valid values and their meanings.
//!
use crate::content_history::ContentHistory;
use crate::mapping_notes::MappingNotes;
use crate::notes::Notes;
use crate::relationships::Relationships;
use crate::structured_text::StructuredText;
use crate::weaknesses::References;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Views {
  #[serde(rename(deserialize = "$value"), default)]
  pub views: Vec<View>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct View {
  #[serde(rename(deserialize = "@ID"))]
  pub id: i64,
  #[serde(rename(deserialize = "@Name"))]
  pub name: String,
  #[serde(rename(deserialize = "@Type"))]
  pub r#type: String,
  #[serde(rename(deserialize = "@Status"))]
  pub status: String,
  #[serde(rename(deserialize = "References"))]
  pub references: Option<References>,
  #[serde(rename(deserialize = "Objective"))]
  pub objective: StructuredText,
  #[serde(rename(deserialize = "Audience"))]
  pub audience: Option<Audience>,
  #[serde(rename(deserialize = "Members"))]
  pub members: Option<Relationships>,
  #[serde(rename(deserialize = "Notes"))]
  pub notes: Option<Notes>,
  #[serde(rename(deserialize = "Filter"))]
  pub filter: Option<String>,
  #[serde(rename(deserialize = "Content_History"))]
  pub content_history: ContentHistory,
  #[serde(rename(deserialize = "Mapping_Notes"))]
  pub mapping_notes: MappingNotes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
  #[serde(rename(deserialize = "$value"), default)]
  pub stake_holders: Vec<StakeHolder>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StakeHolder {
  #[serde(rename(deserialize = "Type"))]
  pub r#type: String,
  #[serde(rename(deserialize = "Description"))]
  pub description: Option<String>,
}
