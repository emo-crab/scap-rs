use crate::cve::Cve;
use crate::cve_knowledge_base::CveKnowledgeBase;
use crate::error::{DBError, DBResult};
use crate::knowledge_base::KnowledgeBase;
use crate::pagination::ListResponse;
use crate::schema::{cve_knowledge_base, cves, knowledge_base};
use crate::DB;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::{ExpressionMethods, Insertable, MysqlConnection, QueryDsl, RunQueryDsl};
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::IntoParams;

#[derive(Insertable, Debug)]
#[diesel(table_name = cve_knowledge_base)]
pub struct CreateCveKB {
  pub cve_id: String,
  pub knowledge_base_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KnowledgeBaseInfo {
  pub kb: KnowledgeBase,
  pub cve: Option<Cve>,
  pub product: Option<KnowledgeBase>,
}

#[derive(Debug)]
pub struct CreateCveKBByName {
  pub cve_id: String,
  pub vendor: String,
  pub product: String,
}

// 返回的CVE产品结构
#[derive(Debug, Serialize, Deserialize)]
pub struct CveKBInfo {
  pub cve: Cve,
  pub kb: KnowledgeBase,
}

#[cfg_attr(feature = "openapi", derive(IntoParams))]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryCveKB {
  pub cve_id: Option<String>,
  pub vendor: Option<String>,
  pub product: Option<String>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}

impl QueryCveKB {
  // 查询参数过滤实现,免得写重复的过滤代码
  // https://github.com/diesel-rs/diesel/discussions/3468
  fn query<'a>(
    &'a self,
    _conn: &mut MysqlConnection,
    mut query: cve_knowledge_base::BoxedQuery<'a, DB>,
  ) -> DBResult<cve_knowledge_base::BoxedQuery<'a, DB>> {
    if let Some(id) = &self.cve_id {
      query = query.filter(cve_knowledge_base::cve_id.eq(id));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, cve_knowledge_base::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(cve_knowledge_base::cve_id))
        .first::<i64>(conn)?,
    )
  }
}

impl CveKnowledgeBase {
  // 创建CVE和产品关联
  pub fn create(conn: &mut MysqlConnection, args: &CreateCveKB) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(cve_knowledge_base::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在弱点
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Ok(
      cve_knowledge_base::dsl::cve_knowledge_base
        .filter(cve_knowledge_base::cve_id.eq(&args.cve_id))
        .filter(cve_knowledge_base::knowledge_base_id.eq(&args.knowledge_base_id))
        .first::<CveKnowledgeBase>(conn)?,
    )
  }
  // 根据cve编号获取exp id列表
  pub fn query_by_cve(conn: &mut MysqlConnection, cve_id: String) -> DBResult<Vec<Vec<u8>>> {
    let args = QueryCveKB {
      cve_id: Some(cve_id),
      vendor: None,
      product: None,
      size: None,
      page: None,
    };
    let query = args.query(conn, cve_knowledge_base::table.into_boxed())?;
    let result = query
      .select(cve_knowledge_base::knowledge_base_id)
      .load::<Vec<u8>>(conn)?;
    Ok(result)
  }
  // 用来删除过期数据
  pub fn delete(
    conn: &mut MysqlConnection,
    cve_id: String,
    knowledge_base_id: Vec<u8>,
  ) -> DBResult<usize> {
    Ok(
      diesel::delete(cve_knowledge_base::table)
        .filter(cve_knowledge_base::cve_id.eq(cve_id))
        .filter(cve_knowledge_base::knowledge_base_id.eq(knowledge_base_id))
        .execute(conn)?,
    )
  }
  // 根据供应商，产品和CVE编号 返回CVE和产品信息
  pub fn query(
    conn: &mut MysqlConnection,
    args: &QueryCveKB,
  ) -> DBResult<ListResponse<CveKBInfo, QueryCveKB>> {
    let total = args.total(conn)?;
    // 限制最大分页为20,防止拒绝服务攻击
    let page = args.page.unwrap_or(0);
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10), 10);
    let result = {
      let kb_ids_query = args.query(conn, cve_knowledge_base::table.into_boxed())?;
      let exp_ids = kb_ids_query
        .offset(page * size)
        .limit(size)
        .select(cve_knowledge_base::knowledge_base_id)
        .load::<Vec<u8>>(conn)?;
      // 联表查要把表写在前面，但是这样就用不了query了，所以先查处cve编号列表再eq_any过滤
      let query = cve_knowledge_base::table
        .inner_join(cves::table)
        .inner_join(knowledge_base::table)
        .into_boxed();
      query
        .filter(cve_knowledge_base::knowledge_base_id.eq_any(exp_ids))
        .load::<(CveKnowledgeBase, Cve, KnowledgeBase)>(conn)?
        .into_iter()
        .map(|(_cp, c, p)| CveKBInfo { cve: c, kb: p })
        .collect::<Vec<_>>()
    };
    Ok(ListResponse::new(result, total, page, size, args.clone()))
  }
}
