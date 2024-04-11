use crate::common::order::OrderBy;
use diesel::expression::expression_types::NotSelectable;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::{BoxableExpression, ExpressionMethods, MysqlConnection, QueryDsl, RunQueryDsl};

use crate::cve::{CreateCve, Cve, QueryCve};
use crate::cve_product::db::ProductByName;
use crate::cve_product::CveProduct;
use crate::error::{DBError, DBResult};
use crate::pagination::ListResponse;
use crate::schema::cves;
use crate::DB;

impl QueryCve {
  // 查询参数过滤实现,免得写重复的过滤代码
  // https://github.com/diesel-rs/diesel/discussions/3468
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: cves::BoxedQuery<'a, DB>,
  ) -> DBResult<cves::BoxedQuery<'a, DB>> {
    if let Some(id) = &self.id {
      query = query.filter(cves::id.eq(id));
    }
    if let Some(year) = &self.year {
      query = query.filter(cves::year.eq(year));
    }
    if let Some(translated) = &self.translated {
      query = query.filter(cves::translated.eq(translated));
    }
    // 根据供应商和产品查询CVE编号，和字段ID冲突
    if self.vendor.is_some() || self.product.is_some() {
      let cve_ids = CveProduct::query_cve_by_product(
        conn,
        &ProductByName {
          vendor: self.vendor.clone(),
          product: self.product.clone(),
        },
      )?;
      query = query.filter(cves::id.eq_any(cve_ids));
    }
    if let Some(severity) = &self.severity {
      query = query.filter(cves::severity.eq(severity.to_lowercase()));
    }
    if let Some(order) = &self.order {
      let o: Box<dyn BoxableExpression<cves::table, _, SqlType = NotSelectable>> = match order.order
      {
        OrderBy::Asc => Box::new(cves::id.asc()),
        OrderBy::Desc => Box::new(cves::id.desc()),
      };
      query = query.order_by(o);
    } else {
      query = query.order_by(cves::id.desc());
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, cves::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(cves::id))
        .first::<i64>(conn)?,
    )
  }
}

impl Cve {
  // 创建CVE
  pub fn create(conn: &mut MysqlConnection, args: &CreateCve) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(cves::table).values(args).execute(conn) {
      // 重复了，说明已经存在CVE
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Self::query_by_id(conn, &args.id)
  }
  pub fn update_translated(conn: &mut MysqlConnection, id: &str, description: &str) {
    if let Ok(mut c) = Cve::query_by_id(conn, id) {
      c.update_description("zh".to_string(), description.to_string());
      diesel::update(cves::table.filter(cves::id.eq(id)))
        .set((
          cves::description.eq(&c.description),
          cves::translated.eq(&c.translated),
          cves::updated_at.eq(&c.updated_at),
        ))
        .execute(conn)
        .unwrap_or_default();
    };
  }
  pub fn create_or_update(conn: &mut MysqlConnection, args: &CreateCve) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(cves::table).values(args).execute(conn) {
      // 重复了，说明已经存在CVE
      return match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
          // 更新这个CVE
          let id = diesel::update(cves::table.filter(cves::id.eq(&args.id)))
            .set((
              cves::assigner.eq(&args.assigner),
              cves::description.eq(&args.description),
              cves::translated.eq(0),
              cves::severity.eq(&args.severity),
              cves::metrics.eq(&args.metrics),
              cves::weaknesses.eq(&args.weaknesses),
              cves::configurations.eq(&args.configurations),
              cves::references.eq(&args.references),
              cves::created_at.eq(&args.created_at),
              cves::updated_at.eq(&args.updated_at),
            ))
            .execute(conn);
          match id {
            Ok(_id) => Self::query_by_id(conn, &args.id),
            Err(err) => Err(DBError::DieselError { source: err }),
          }
        }
        _ => Err(DBError::DieselError { source: err }),
      };
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Self::query_by_id(conn, &args.id)
  }
  // 查单个cve不联cvss表
  pub fn query_by_id(conn: &mut MysqlConnection, id: &str) -> DBResult<Self> {
    Ok(cves::dsl::cves.filter(cves::id.eq(id)).first::<Cve>(conn)?)
  }
  // 按照查询条件返回列表和总数
  pub fn query(
    conn: &mut MysqlConnection,
    args: &QueryCve,
  ) -> DBResult<ListResponse<Cve, QueryCve>> {
    let total = args.total(conn)?;
    // 限制最大分页为20,防止拒绝服务攻击
    let page = args.page.unwrap_or(0).abs();
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10).abs(), 10);
    let result = {
      let query = args.query(conn, cves::table.into_boxed())?;
      query.offset(page * size).limit(size).load::<Cve>(conn)?
    };
    Ok(ListResponse::new(result, total, page, size, args.clone()))
  }
}
