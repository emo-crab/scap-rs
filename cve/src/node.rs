use serde::{Deserialize, Serialize, Serializer};
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
pub enum CPE23 {
  #[cfg(not(feature = "cpe"))]
  Value(String),
  #[cfg(feature = "cpe")]
  #[serde(deserialize_with = "cpe::dictionary::uri_to_attribute")]
  Attributes(cpe::CPEAttributes),
}

fn cpe23_string_serialize<S>(cpe: &CPE23, s: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  match cpe {
    #[cfg(not(feature = "cpe"))]
    CPE23::Value(v) => s.serialize_str(v),
    #[cfg(feature = "cpe")]
    CPE23::Attributes(c) => s.serialize_str(&c.to_string()),
  }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Match {
  // 是否存在漏洞
  pub vulnerable: bool,
  // CPE
  #[serde(rename = "cpe23Uri", serialize_with = "cpe23_string_serialize")]
  pub cpe23_uri: CPE23,
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
