use diesel::{BelongingToDsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use helper::init_db_pool;
use nvd_api::models::cve_product_db::CreateCveProductByName;
use nvd_api::models::{CveProduct, Product, Vendor};
use nvd_api::schema::{products, vendors};
use std::ops::DerefMut;
// mysql> drop database nvd;
// Query OK, 7 rows affected (0.04 sec)
//
// mysql> RESET MASTER;
// Query OK, 0 rows affected (0.01 sec)
//
// mysql> RESET SLAVE;
// Query OK, 0 rows affected, 1 warning (0.00 sec)
//
// mysql> PURGE BINARY LOGS BEFORE NOW();
// Query OK, 0 rows affected, 1 warning (0.00 sec)

fn main() {
  let connection_pool = init_db_pool();
  // 联表查询
  let vendor_id: Vendor = vendors::table
    .filter(vendors::name.eq("microsoft"))
    .first(connection_pool.get().unwrap().deref_mut())
    .unwrap();
  let product = Product::belonging_to(&vendor_id)
    .filter(products::name.eq("windows_nt"))
    .first::<Product>(connection_pool.get().unwrap().deref_mut())
    .unwrap();
  println!("{product:?}");
  let cp = CreateCveProductByName {
    cve_id: "CVE-1999-0595".to_string(),
    vendor: "microsoft".to_string(),
    product: "windows_nt".to_string(),
  };
  CveProduct::create_by_name(connection_pool.get().unwrap().deref_mut(), &cp).unwrap();
}
