use crate::error::{NVDApiError, Result};
use crate::models::{Cve, CveProduct, Product, Vendor};
use crate::models::product_db::{QueryProductById, QueryProductByVendorName};
use crate::schema::{cve_product, cves, products};
use crate::DB;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};

#[derive(Insertable)]
#[diesel(table_name = cve_product)]
pub struct CreateCveProduct {
  pub cve_id: String,
  pub product_id: Vec<u8>,
}
#[derive(Debug)]
pub struct CreateCveProductByName {
  pub cve_id: String,
  pub vendor: String,
  pub product: String,
}

// 返回的CVE产品结构
#[derive(Debug, Serialize, Deserialize)]
pub struct CveProductInfo {
  pub cve: Cve,
  pub product: Product,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveProductInfoCount {
  pub result: Vec<CveProductInfo>,
  pub total: i64,
}
pub struct ProductByName {
  pub vendor: Option<String>,
  pub product: Option<String>,
}
#[derive(Debug)]
pub struct QueryCveProduct {
  pub cve_id: Option<String>,
  pub vendor: Option<String>,
  pub product: Option<String>,
  pub limit: Option<i64>,
  pub offset: Option<i64>,
}

impl QueryCveProduct {
  // 查询参数过滤实现,免得写重复的过滤代码
  // https://github.com/diesel-rs/diesel/discussions/3468
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: cve_product::BoxedQuery<'a, DB>,
  ) -> Result<cve_product::BoxedQuery<'a, DB>> {
    // 如果有提供商名称，查询精准名称，返回该提供商旗下全部产品
    if let Some(vendor_name) = &self.vendor {
      let v = Vendor::query_by_name(conn, vendor_name)?;
      if let Some(product_name) = &self.product {
        let p = Product::query_by_id(
          conn,
          &QueryProductById {
            vendor_id: v.id,
            name: product_name.to_string(),
          },
        )?;
        query = query.filter(cve_product::product_id.eq(p.id));
      } else {
        let ids = Product::belonging_to(&v)
          .select(products::id)
          .load::<Vec<u8>>(conn)?;
        query = query.filter(cve_product::product_id.eq_any(ids));
      }
    } else {
      // 只有产品的
      if let Some(name) = &self.product {
        let ids = products::table
          .select(products::id)
          .filter(products::name.like(format!("%{name}%")))
          .load::<Vec<u8>>(conn)?;
        query = query.filter(cve_product::product_id.eq_any(ids));
      }
    }
    if let Some(id) = &self.cve_id {
      query = query.filter(cve_product::cve_id.eq(id));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> Result<i64> {
    let query = self.query(conn, cve_product::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(cve_product::cve_id))
        .first::<i64>(conn)?,
    )
  }
}

impl CveProduct {
  // 创建CVE和产品关联
  pub fn create(conn: &mut MysqlConnection, args: &CreateCveProduct) -> Result<Self> {
    if let Err(err) = diesel::insert_into(cve_product::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在弱点
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDApiError::DieselError { source: err });
        }
      }
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Ok(
      cve_product::dsl::cve_product
        .filter(cve_product::cve_id.eq(&args.cve_id))
        .filter(cve_product::product_id.eq(&args.product_id))
        .first::<CveProduct>(conn)?,
    )
  }
  // 创建CVE和产品关联从名称
  pub fn create_by_name(conn: &mut MysqlConnection, args: &CreateCveProductByName) -> Result<Self> {
    let vp = QueryProductByVendorName {
      vendor_name: args.vendor.clone(),
      name: args.product.clone(),
    };
    let p = Product::query_by_vendor_name(conn, &vp)?;
    Self::create(
      conn,
      &CreateCveProduct {
        cve_id: args.cve_id.clone(),
        product_id: p.id,
      },
    )
  }
  // 根据供应商和产品查询CVE编号列表
  pub fn query_cve_by_product(
    conn: &mut MysqlConnection,
    args: &ProductByName,
  ) -> Result<Vec<String>> {
    // 根据供应商和产品过滤
    let ProductByName { vendor, product } = args;
    let args = QueryCveProduct {
      cve_id: None,
      vendor: vendor.clone(),
      product: product.clone(),
      limit: None,
      offset: None,
    };
    let query = args.query(conn, cve_product::table.into_boxed())?;
    let cve_id = query.select(cve_product::cve_id).load::<String>(conn)?;
    Ok(cve_id)
  }
  // 根据供应商，产品和CVE编号 返回CVE和产品信息
  pub fn query(conn: &mut MysqlConnection, args: &QueryCveProduct) -> Result<CveProductInfoCount> {
    let total = args.total(conn)?;
    let result = {
      let cve_ids_query = args.query(conn, cve_product::table.into_boxed())?;
      let cve_ids = cve_ids_query
        .offset(args.offset.unwrap_or(0))
        .limit(args.limit.map_or(20, |l| if l > 20 { 20 } else { l }))
        .select(cve_product::cve_id)
        .load::<String>(conn)?;
      // 联表查要把表写在前面，但是这样就用不了query了，所以先查处cve编号列表再eq_any过滤
      let query = cve_product::table
        .inner_join(cves::table)
        .inner_join(products::table)
        .into_boxed();
      query
        .filter(cve_product::cve_id.eq_any(cve_ids))
        .load::<(CveProduct, Cve, Product)>(conn)?
        .into_iter()
        .map(|(_cp, c, p)| CveProductInfo { cve: c, product: p })
        .collect::<Vec<_>>()
    };
    Ok(CveProductInfoCount { total, result })
  }
}
