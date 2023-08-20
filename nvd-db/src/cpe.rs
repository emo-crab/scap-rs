use crate::schema::{products, vendors};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Insertable)]
#[table_name = "vendors"]
pub struct NewVendors {
  pub id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
}

#[derive(Insertable)]
#[table_name = "products"]
pub struct NewProducts {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
}
