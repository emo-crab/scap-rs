//! configurations
//!
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

///  A configuration is a container that holds a set of nodes which then contain CPE Name Match Criteria. Configurations consist of three different types.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configurations {
  // 版本
  #[serde(rename = "CVE_data_version")]
  pub data_version: String,
  // 漏洞节点
  pub nodes: Vec<Node>,
}

impl Configurations {
  pub fn unique_vendor_product(&self) -> Vec<nvd_cpe::Product> {
    self
      .nodes
      .iter()
      .flat_map(|node| node.vendor_product())
      .collect()
  }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
  // 逻辑操作符
  #[serde(default)]
  pub operator: Operator,
  #[serde(default)]
  pub negate: bool,
  // 子节点
  #[serde(default)]
  pub children: Vec<Node>,
  // CPE 匹配列表
  #[serde(alias = "cpeMatch", default)]
  pub cpe_match: Vec<Match>,
}

/// Applicability statements are made to withstand changes to the Official CPE Dictionary without requiring consistent maintenance. CPE Match criteria comes in two forms CPE Match Strings and CPE Match String Ranges. Each of these are abstract concepts that are then correlated to CPE Names in the Official CPE Dictionary. Match criteria are displayed in bold text within a configuration node.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Match {
  // 是否为漏洞组件,如果为假，就是运行环境,在api接口中没有下面的版本信息才是运行环境
  #[serde(default)]
  pub vulnerable: bool,
  #[serde(alias = "criteria")]
  pub cpe23_uri: String,
  // 包括 从版本开始
  pub version_start_including: Option<String>,
  // 排除 从版本开始
  pub version_start_excluding: Option<String>,
  // 包括 到版本结束
  pub version_end_including: Option<String>,
  // 排除 到版本结束
  pub version_end_excluding: Option<String>,
  pub created: Option<NaiveDateTime>,
  pub last_modified: Option<NaiveDateTime>,
  pub cpe_last_modified: Option<NaiveDateTime>,
  #[serde(default)]
  pub status: MatchStatus,
  #[serde(rename = "cpe_name", alias = "matches", default)]
  pub matches: Vec<Matches>,
  pub match_criteria_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub enum MatchStatus {
  Active,
  Inactive,
}

impl Default for MatchStatus {
  fn default() -> Self {
    Self::Active
  }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Matches {
  pub cpe_name: String,
  pub cpe_name_id: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "UPPERCASE", deny_unknown_fields)]
pub enum Operator {
  And,
  Or,
}

impl Default for Operator {
  fn default() -> Self {
    Self::Or
  }
}

impl Match {
  pub fn is_vulnerable(&self) -> bool {
    if self.vulnerable {
      true
    } else {
      self.version_start_including.is_some()
        || self.version_start_excluding.is_some()
        || self.version_end_including.is_some()
        || self.version_end_excluding.is_some()
    }
  }
  pub fn has_version_range(&self) -> bool {
    self.version_start_including.is_some()
      || self.version_start_excluding.is_some()
      || self.version_end_including.is_some()
      || self.version_end_excluding.is_some()
  }
  pub fn product(&self) -> nvd_cpe::Product {
    match nvd_cpe::CPEName::from_uri(&self.cpe23_uri) {
      Ok(name) => nvd_cpe::Product::from(&name),
      Err(_) => nvd_cpe::Product::default(),
    }
  }
  pub fn get_version_range(&self) -> String {
    let mut version = None;
    let mut op_start = None;
    let mut op_end = None;
    let mut v_start = None;
    let mut v_end = None;
    if let Ok(name) = nvd_cpe::CPEName::from_uri(&self.cpe23_uri) {
      if !(name.version.matches("*") || name.version.matches("-")) {
        op_start = Some("=");
      }
      version = Some(name.version.to_string());
    };
    if let Some(start_inc) = &self.version_start_including {
      op_start = Some(">=");
      v_start = Some(start_inc.as_str());
    }
    if let Some(start_exc) = &self.version_start_excluding {
      op_start = Some(">");
      v_start = Some(start_exc.as_str());
    }
    if let Some(end_inc) = &self.version_end_including {
      op_end = Some("<=");
      v_end = Some(end_inc.as_str());
    }
    if let Some(end_exc) = &self.version_end_excluding {
      op_end = Some("<");
      v_end = Some(end_exc.as_str());
    }
    // 什么都没有的
    if v_start.is_none() && v_end.is_none() {
      format!("{} {}", op_start.unwrap_or(""), version.unwrap_or_default())
    } else {
      format!(
        "{}{} {} {}{}",
        v_start.unwrap_or(""),
        op_start.unwrap_or(""),
        version.unwrap_or_default(),
        op_end.unwrap_or(""),
        v_end.unwrap_or_default()
      )
    }
  }
  pub fn match_version_range(&self, ver: &str) -> bool {
    if let Some(start_inc) = &self.version_start_including {
      if !nvd_cpe::version_cmp(ver, start_inc, ">=") {
        return false;
      }
    }

    if let Some(start_exc) = &self.version_start_excluding {
      if !nvd_cpe::version_cmp(ver, start_exc, ">") {
        return false;
      }
    }

    if let Some(end_inc) = &self.version_end_including {
      if !nvd_cpe::version_cmp(ver, end_inc, "<=") {
        return false;
      }
    }

    if let Some(end_exc) = &self.version_end_excluding {
      if !nvd_cpe::version_cmp(ver, end_exc, "<") {
        return false;
      }
    }
    true
  }

  pub fn is_match(&self, product: &str, version: &str) -> bool {
    if let Ok(name) = nvd_cpe::CPEName::from_uri(&self.cpe23_uri) {
      if name.match_product(product) {
        if self.has_version_range() {
          return self.match_version_range(version);
        }
        return name.match_version(version);
      }
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
  pub fn vendor_product(&self) -> HashSet<nvd_cpe::Product> {
    // 只获取有漏洞的组件，运行环境不关联cve
    let product = self
      .cpe_match
      .iter()
      .filter(|m| m.is_vulnerable())
      .map(|m| m.product());
    let children = self.children.iter().flat_map(|node| node.vendor_product());
    product.chain(children).collect()
  }
}
