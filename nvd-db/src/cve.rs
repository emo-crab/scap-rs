use chrono::NaiveDateTime;
use crate::error::{NVDDBError, Result};
use crate::models::{Cve};
use crate::schema::{cves};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::sql_types::Json;
use serde_json::Value;

#[derive(Debug,Insertable)]
#[diesel(table_name = cves)]
pub struct NewCve {
    pub id: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub references: Json,
    pub description: Json,
    pub cwe: Json,
    pub cvss3_id: Option<Vec<u8>>,
    pub cvss2_id: Option<Vec<u8>>,
    pub raw: Json,
    pub assigner: String,
    pub product_id: Vec<u8>,
    pub configurations: Json,
    pub official: u8,
}

impl Cve {
    // 创建弱点枚举
    pub fn create(conn: &mut MysqlConnection, args: &NewCve) -> Result<Self> {
        if let Err(err) = diesel::insert_into(cves::table)
            .values(args)
            .execute(conn)
        {
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
            cves::dsl::cves
                .filter(cves::id.eq(&args.id))
                .first::<Cve>(conn)?,
        )
    }
}
