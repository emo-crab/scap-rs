
use chrono::NaiveDateTime;
use diesel::prelude::*;
#[derive(Queryable, Debug, Clone)]
pub struct Product {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Selectable, PartialEq, Debug, Clone)]
#[diesel(table_name = crate::schema::vendors)]
pub struct Vendor {
  pub id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
