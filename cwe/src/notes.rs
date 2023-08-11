use serde::Deserialize;
use crate::structured_text::StructuredTextType;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
    #[serde(rename = "$value")]
    pub notes: Vec<Note>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    #[serde(rename = "@Type")]
    pub r#type: Option<String>,
    #[serde(rename = "$value")]
    pub content: Vec<StructuredTextType>,
}