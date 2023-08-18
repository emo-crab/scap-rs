use chrono::NaiveDateTime;
// #[derive(Identifiable, Queryable, Debug, Serialize, Deserialize, Associations, Clone)]
// #[diesel(belongs_to(User, foreign_key = author_id))]
// #[diesel(table_name = cve)]
pub struct CVE {
  // CVE 编号
  pub cve_id: String,
  pub vendors: String,
  pub description: String,
  // cvss 评分
  pub base_metric_v3: u32,
  // 弱点
  pub cwe: u32,
  pub published_date: NaiveDateTime,
  pub last_modified_date: NaiveDateTime,
  // 引用参考链接
  pub references: String,
  // cpe厂商产品 匹配
  pub configurations: u32,
}
