use crate::schema::{products, vendors};
use diesel::prelude::*;

#[derive(Insertable)]
#[diesel(table_name = vendors)]
pub struct NewVendors {
  pub id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub official: u8,
}

#[derive(Insertable)]
#[diesel(table_name = products)]
pub struct NewProducts {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub official: u8,
  pub part: String,
}

pub struct DeleteProducts {
  pub name: String,
  pub vendor_id: Vec<u8>,
}
