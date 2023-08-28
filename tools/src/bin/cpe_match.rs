use nvd_db::models::{ Product, Vendor};
use nvd_db::schema::{products, vendors};
use std::ops::DerefMut;
use diesel::{BelongingToDsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use tools::init_db_pool;


fn main() {
    let connection_pool = init_db_pool();
    // 联表查询
    let vendor_id:Vendor = vendors::table
        .filter(vendors::name.eq("74cms"))
        .first(connection_pool.get().unwrap().deref_mut()).unwrap();
    let product = Product::belonging_to(&vendor_id)
        .filter(products::name.eq("74cms")).
        first::<Product>(connection_pool.get().unwrap().deref_mut()).unwrap();
    println!("{product:?}");
}
