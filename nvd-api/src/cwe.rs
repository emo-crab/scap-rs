use crate::error::{NVDDBError, Result};
use crate::models::Cwe;
use crate::schema::cwes;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

#[derive(Insertable)]
#[diesel(table_name = cwes)]
pub struct CreateCwe {
  pub id: i32,
  pub name: String,
  pub description: String,
}

impl Cwe {
  // 创建弱点枚举
  pub fn create(conn: &mut MysqlConnection, args: &CreateCwe) -> Result<Self> {
    if let Err(err) = diesel::insert_into(cwes::table).values(args).execute(conn) {
      // 重复了，说明已经存在弱点
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
        }
      }
    }
    Ok(
      // mysql 不支持 get_result，要再查一次得到插入结果
      cwes::dsl::cwes
        .filter(cwes::name.eq(&args.name))
        .first::<Cwe>(conn)?,
    )
  }
}
