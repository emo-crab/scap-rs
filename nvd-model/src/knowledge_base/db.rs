use std::fmt::{Display, Formatter};

use chrono::NaiveDateTime;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::{ExpressionMethods, Insertable, MysqlConnection, QueryDsl, RunQueryDsl};

use crate::cve_knowledge_base::CveKnowledgeBase;
use crate::error::{DBError, DBResult};
use crate::knowledge_base::{KnowledgeBase, QueryKnowledgeBase};
use crate::pagination::ListResponse;
use crate::schema::{cve_knowledge_base, knowledge_base};
use crate::types::{AnyValue, MetaData};
use crate::DB;

#[derive(Clone, Copy)]
pub enum KBSource {
  ExploitDb,
  NucleiTemplates,
  Metasploit,
  AttackerKB,
}

#[derive(Clone, Copy)]
pub enum KBTypes {
  Exploit,
  KnowledgeBase,
}

impl Display for KBTypes {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      KBTypes::Exploit => f.write_str("exploit"),
      KBTypes::KnowledgeBase => f.write_str("knowledge-base"),
    }
  }
}

impl Display for KBSource {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      KBSource::ExploitDb => f.write_str("exploit-db"),
      KBSource::NucleiTemplates => f.write_str("nuclei-templates"),
      KBSource::Metasploit => f.write_str("metasploit"),
      KBSource::AttackerKB => f.write_str("attackerkb"),
    }
  }
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = knowledge_base)]
pub struct CreateKnowledgeBase {
  pub id: Vec<u8>,
  pub name: String,
  pub source: String,
  pub types: String,
  pub description: String,
  pub path: String,
  pub meta: AnyValue<MetaData>,
  pub verified: u8,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

impl QueryKnowledgeBase {
  // 查询参数过滤实现,免得写重复的过滤代码
  // https://github.com/diesel-rs/diesel/discussions/3468
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: knowledge_base::BoxedQuery<'a, DB>,
  ) -> DBResult<knowledge_base::BoxedQuery<'a, DB>> {
    // 如果有提供商名称，查询精准名称，返回该提供商旗下全部产品
    if let Some(source) = &self.source {
      query = query.filter(knowledge_base::source.eq(source));
    }
    if let Some(name) = &self.name {
      query = query.filter(knowledge_base::name.eq(name));
    }
    if let Some(verified) = &self.verified {
      query = query.filter(knowledge_base::verified.eq(verified));
    }
    if let Some(link) = &self.path {
      query = query.filter(knowledge_base::path.eq(link));
    }
    if let Some(cve_id) = &self.cve {
      // 根据cve编号获取exp id 列表
      let exp_ids = CveKnowledgeBase::query_by_cve(conn, cve_id.clone())?;
      query = query.filter(knowledge_base::id.eq_any(exp_ids));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, knowledge_base::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(knowledge_base::id))
        .first::<i64>(conn)?,
    )
  }
}

impl KnowledgeBase {
  // 创建漏洞利用
  pub fn create(conn: &mut MysqlConnection, args: &CreateKnowledgeBase) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(knowledge_base::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在漏洞利用
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Ok(
      knowledge_base::dsl::knowledge_base
        .filter(knowledge_base::name.eq(&args.name))
        .filter(knowledge_base::source.eq(&args.source))
        .filter(knowledge_base::path.eq(&args.path))
        .first::<KnowledgeBase>(conn)?,
    )
  }
  pub fn create_or_update(
    conn: &mut MysqlConnection,
    args: &CreateKnowledgeBase,
  ) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(knowledge_base::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在KB
      return match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
          // 更新这个KB
          let id = diesel::update(
            knowledge_base::table
              .filter(knowledge_base::name.eq(&args.name))
              .filter(knowledge_base::types.eq(&args.types))
              .filter(knowledge_base::source.eq(&args.source)),
          )
          .set((
            knowledge_base::path.eq(&args.path),
            knowledge_base::meta.eq(&args.meta),
            knowledge_base::description.eq(&args.description),
            knowledge_base::verified.eq(&args.verified),
            knowledge_base::created_at.eq(&args.created_at),
            knowledge_base::updated_at.eq(&args.updated_at),
          ))
          .execute(conn);
          match id {
            Ok(_id) => Self::query_by_name_source(conn, &args.name, &args.source),
            Err(err) => Err(DBError::DieselError { source: err }),
          }
        }
        _ => Err(DBError::DieselError { source: err }),
      };
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Self::query_by_name_source(conn, &args.name, &args.source)
  }
  pub fn delete(conn: &mut MysqlConnection, name: &str, source: KBSource) -> DBResult<usize> {
    let kb = Self::query_by_name_source(conn, name, &source.to_string())?;
    diesel::delete(cve_knowledge_base::table)
      .filter(cve_knowledge_base::knowledge_base_id.eq(kb.id))
      .execute(conn)?;
    Ok(
      diesel::delete(knowledge_base::table)
        .filter(knowledge_base::name.eq(name))
        .filter(knowledge_base::source.eq(source.to_string()))
        .execute(conn)?,
    )
  }
  pub fn query_by_name_source(
    conn: &mut MysqlConnection,
    name: &str,
    source: &str,
  ) -> DBResult<Self> {
    Ok(
      knowledge_base::dsl::knowledge_base
        .filter(knowledge_base::name.eq(name))
        .filter(knowledge_base::source.eq(source))
        .first::<KnowledgeBase>(conn)?,
    )
  }
  pub fn query_by_cve(conn: &mut MysqlConnection, id: &str) -> DBResult<Vec<Self>> {
    // 还有在meta里的json过滤存在cve的，没找到json的过滤方法，实在不行就使用sql_query执行原生sql
    Ok(
      knowledge_base::dsl::knowledge_base
        .filter(knowledge_base::name.eq(id))
        // .or_filter(knowledge_base::meta)
        .load::<KnowledgeBase>(conn)?,
    )
  }
  // 查询knowledge_base信息
  pub fn query(
    conn: &mut MysqlConnection,
    args: &QueryKnowledgeBase,
  ) -> DBResult<ListResponse<KnowledgeBase, QueryKnowledgeBase>> {
    let total = args.total(conn)?;
    // 限制最大分页为20,防止拒绝服务攻击
    let page = args.page.unwrap_or(0);
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10), 10);
    let result = {
      let query = args.query(conn, knowledge_base::table.into_boxed())?;
      query
        .order(knowledge_base::updated_at.desc())
        .offset(page * size)
        .limit(size)
        .load::<KnowledgeBase>(conn)?
    };
    Ok(ListResponse::new(result, total, page, size, args.clone()))
  }
}
