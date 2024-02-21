#[cfg(feature = "db")]
use diesel::{Associations, Identifiable, Queryable, Selectable};

#[cfg(feature = "db")]
use crate::cve::Cve;
#[cfg(feature = "db")]
use crate::knowledge_base::KnowledgeBase;
#[cfg(feature = "db")]
use crate::schema::cve_knowledge_base;

#[cfg(feature = "db")]
pub mod db;

#[cfg_attr(feature = "db", derive(Queryable, Selectable, Identifiable, Associations), diesel(table_name = cve_knowledge_base, belongs_to(Cve), belongs_to(KnowledgeBase), primary_key(cve_id, knowledge_base_id)))]
#[derive(Debug, PartialEq)]
pub struct CveKnowledgeBase {
  pub cve_id: String,
  pub knowledge_base_id: Vec<u8>,
}
