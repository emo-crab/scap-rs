use crate::kb::create_or_update_exploit;
use crate::kb::serde_format::string_to_hashset;
use chrono::Utc;
use nvd_model::knowledge_base::db::{CreateKnowledgeBase, KBSource, KBTypes};
use nvd_model::types::{AnyValue, MetaData};
use nvd_model::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Template {
  pub id: String,
  pub info: Info,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Info {
  pub name: String,
  pub description: String,
  pub classification: Option<Classification>,
  #[serde(deserialize_with = "string_to_hashset")]
  pub tags: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Classification {
  #[serde(rename = "cve-id")]
  pub cve_id: Option<String>,
  pub cpe: Option<String>,
}

impl From<Template> for CreateKnowledgeBase {
  fn from(val: Template) -> Self {
    let template = val;
    CreateKnowledgeBase {
      id: uuid::Uuid::new_v4().as_bytes().to_vec(),
      name: template.id.clone(),
      description: template.info.description,
      source: KBSource::NucleiTemplates.to_string(),
      meta: AnyValue::new(MetaData::from_hashset("tags", template.info.tags)),
      verified: 1,
      created_at: Utc::now().naive_utc(),
      updated_at: Utc::now().naive_utc(),
      path: String::new(),
      types: KBTypes::Exploit.to_string(),
    }
  }
}
impl Template {
  pub fn update(&self, conn: &mut Connection, path: String) {
    let mut new_exp: CreateKnowledgeBase = self.clone().into();
    new_exp.path = path;
    if let Err(err) = create_or_update_exploit(conn, &new_exp, Some(new_exp.clone().name)) {
      println!("import nuclei knowledge_base err: {:?}", err);
    }
  }
}
