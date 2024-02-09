#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use crate::cve::Cve;
#[cfg(feature = "db")]
use crate::product::Product;
#[cfg(feature = "db")]
use crate::schema::cve_product;
#[cfg(feature = "db")]
use diesel::{Associations, Identifiable, Queryable, Selectable};
#[cfg_attr(feature = "db",
derive(Queryable,Identifiable,Associations,Selectable),
diesel(table_name = cve_product,belongs_to(Cve),belongs_to(Product),primary_key(cve_id, product_id)))]
#[derive(Debug, PartialEq)]
pub struct CveProduct {
  pub cve_id: String,
  pub product_id: Vec<u8>,
}
