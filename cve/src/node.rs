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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Match {
  // 是否存在漏洞
  pub vulnerable: bool,
  // CPE
  #[serde(
    serialize_with = "cpe::dictionary::attribute_to_uri",
    deserialize_with = "cpe::dictionary::uri_to_attribute"
  )]
  pub cpe23_uri: cpe::CPEAttributes,
  // 包括 从版本开始
  pub version_start_including: Option<String>,
  // 排除 从版本开始
  pub version_start_excluding: Option<String>,
  // 包括 到版本结束
  pub version_end_including: Option<String>,
  // 排除 到版本结束
  pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operator {
  And,
  Or,
}

impl Match {
  pub fn has_version_range(&self) -> bool {
    self.version_start_including.is_some()
      || self.version_start_excluding.is_some()
      || self.version_end_including.is_some()
      || self.version_end_excluding.is_some()
  }

  pub fn match_version_range(&self, ver: &str) -> bool {
    if let Some(start_inc) = &self.version_start_including {
      if !cpe::version_cmp(ver, start_inc, ">=") {
        return false;
      }
    }

    if let Some(start_exc) = &self.version_start_excluding {
      if !cpe::version_cmp(ver, start_exc, ">") {
        return false;
      }
    }

    if let Some(end_inc) = &self.version_end_including {
      if !cpe::version_cmp(ver, end_inc, "<=") {
        return false;
      }
    }

    if let Some(end_exc) = &self.version_end_excluding {
      if !cpe::version_cmp(ver, end_exc, "<") {
        return false;
      }
    }
    true
  }

  pub fn is_match(&self, product: &str, version: &str) -> bool {
    if self.cpe23_uri.match_product(product) {
      if self.has_version_range() {
        return self.match_version_range(version);
      }
      return self.cpe23_uri.match_version(version);
    }
    false
  }
}

impl Node {
  pub fn is_match(&self, product: &str, version: &str) -> bool {
    if !self.cpe_match.is_empty() {
      match &self.operator {
        Operator::Or => {
          for cpe_match in &self.cpe_match {
            if cpe_match.is_match(product, version) {
              return true;
            }
          }
        }
        Operator::And => {
          for cpe_match in &self.cpe_match {
            if !cpe_match.is_match(product, version) {
              return false;
            }
          }
          return true;
        }
      }
    } else {
      match &self.operator {
        Operator::Or => {
          for child in &self.children {
            if child.is_match(product, version) {
              return true;
            }
          }
        }
        Operator::And => {
          for child in &self.children {
            if !child.is_match(product, version) {
              return false;
            }
          }
          return true;
        }
      }
    }
    false
  }
}
