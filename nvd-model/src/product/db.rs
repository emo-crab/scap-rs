use crate::error::{DBError, DBResult};
use crate::pagination::ListResponse;
use crate::product::{Product, ProductWithVendor, QueryProduct};
use crate::schema::{products, vendors};
use crate::vendor::Vendor;
use crate::DB;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::Value;

#[derive(Insertable)]
#[diesel(table_name = products)]
pub struct CreateProduct {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub meta: Value,
  pub name: String,
  pub description: Option<String>,
}

pub struct UpdateProduct {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub vendor_name: String,
  pub meta: Value,
  pub name: String,
  pub description: Option<String>,
}

pub struct QueryProductById {
  pub vendor_id: Vec<u8>,
  pub name: String,
}

pub struct QueryProductByVendorName {
  pub vendor_name: String,
  pub name: String,
}

impl QueryProduct {
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: products::BoxedQuery<'a, DB>,
  ) -> DBResult<products::BoxedQuery<'a, DB>> {
    if let Some(name) = &self.vendor_name {
      let v = Vendor::query_by_name(conn, name)?;
      query = query.filter(products::vendor_id.eq(v.id));
    }
    if let Some(part) = &self.part {
      query = query.filter(products::part.eq(part));
    }
    if let Some(name) = &self.name {
      let name = format!("{name}%");
      query = query.filter(products::name.like(name));
    }
    if let Some(official) = &self.official {
      query = query.filter(products::official.eq(official));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, products::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(products::id))
        .first::<i64>(conn)?,
    )
  }
}

impl Product {
  // 创建产品
  pub fn create(conn: &mut MysqlConnection, args: &CreateProduct) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(products::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在该产品
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    Self::query_by_id(
      conn,
      &QueryProductById {
        vendor_id: args.vendor_id.clone(),
        name: args.name.clone(),
      },
    )
  }
  pub fn update(conn: &mut MysqlConnection, args: &UpdateProduct) -> DBResult<Self> {
    let product_id = QueryProductById {
      vendor_id: args.vendor_id.clone(),
      name: args.name.clone(),
    };
    // 更新这个Product
    let id = diesel::update(products::table.filter(products::id.eq(&args.id)))
      .set((
        products::meta.eq(&args.meta),
        products::description.eq(&args.description),
      ))
      .execute(conn);
    match id {
      Ok(_id) => Self::query_by_id(conn, &product_id),
      Err(err) => Err(DBError::DieselError { source: err }),
    }
  }

  // 查询产品从提供商的id
  pub fn query_by_id(conn: &mut MysqlConnection, args: &QueryProductById) -> DBResult<Self> {
    Ok(
      products::dsl::products
        .filter(products::vendor_id.eq(&args.vendor_id))
        .filter(products::name.eq(&args.name))
        .first::<Product>(conn)?,
    )
  }

  // 查询产品从提供商的名称
  pub fn query_by_vendor_name(
    conn: &mut MysqlConnection,
    args: &QueryProductByVendorName,
  ) -> DBResult<Self> {
    let v: Vendor = vendors::table
      .filter(vendors::name.eq(&args.vendor_name))
      .first(conn)?;
    let p: Product = Product::belonging_to(&v)
      .filter(products::name.eq(&args.name))
      .first(conn)?;
    Ok(p)
  }

  pub fn query(
    conn: &mut MysqlConnection,
    args: &QueryProduct,
  ) -> DBResult<ListResponse<ProductWithVendor>> {
    let total = args.total(conn)?;
    let page = args.page.unwrap_or(0).abs();
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10).abs(), 10);
    let result = {
      let products_with_vendors = args.query(conn, products::table.into_boxed())?;
      // 联表查要把表写在前面，但是这样就用不了query了，所以先查处产品ID列表再eq_any过滤
      products_with_vendors
        .inner_join(vendors::table)
        .offset(page * size)
        .limit(size)
        .select((Product::as_select(), Vendor::as_select()))
        .load(conn)?
        .into_iter()
        .map(|(p, v)| ProductWithVendor {
          vendor: v,
          product: p,
        })
        .collect::<Vec<_>>()
    };
    Ok(ListResponse::new(result, total, page, size))
  }
}
