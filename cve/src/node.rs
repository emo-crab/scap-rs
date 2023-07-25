use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
  // 逻辑操作符
  pub operator: Operator,
  // 字节点
  pub children: Vec<Node>,
  // CPE 匹配列表
  pub cpe_match: Vec<Match>,
}
// 字符串或者解析后的，如果想解析需要开启cpe特性
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum CPE32 {
  #[cfg(not(feature = "cpe"))]
  Value(String),
  #[cfg(feature = "cpe")]
  #[serde(deserialize_with = "cpe::dictionary::uri_to_attribute")]
  Attributes(cpe::CPEAttributes),
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Match {
  // 是否存在漏洞
  pub vulnerable: bool,
  // CPE
  #[serde(rename = "cpe23Uri")]
  pub cpe23_uri: CPE32,
  // 包括 从版本开始
  #[serde(rename = "versionStartIncluding")]
  pub version_start_including: Option<String>,
  // 排除 从版本开始
  #[serde(rename = "versionStartExcluding")]
  pub version_start_excluding: Option<String>,
  // 包括 到版本结束
  #[serde(rename = "versionEndIncluding")]
  pub version_end_including: Option<String>,
  // 排除 到版本结束
  #[serde(rename = "versionEndExcluding")]
  pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operator {
  And,
  Or,
}
