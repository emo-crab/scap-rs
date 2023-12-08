use crate::structured_text::StructuredTextType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
  #[serde(rename(deserialize = "$value"))]
  pub notes: Vec<Note>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
  #[serde(rename(deserialize = "@Type"))]
  pub r#type: Option<String>,
  #[serde(rename(deserialize = "$value"))]
  pub content: Vec<StructuredTextType>,
}
