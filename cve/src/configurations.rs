//! configurations
//!
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
  pub fn unique_vendor_product(&self) -> Vec<cpe::Product> {
    self
      .nodes
      .iter()
      .map(|node| node.vendor_product())
      .flatten()
      .collect()
  }
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
  // 逻辑操作符
  pub operator: Operator,
  // 字节点
  pub children: Vec<Node>,
  // CPE 匹配列表
  pub cpe_match: Vec<Match>,
}
/// Applicability statements are made to withstand changes to the Official CPE Dictionary without requiring consistent maintenance. CPE Match criteria comes in two forms CPE Match Strings and CPE Match String Ranges. Each of these are abstract concepts that are then correlated to CPE Names in the Official CPE Dictionary. Match criteria are displayed in bold text within a configuration node.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Match {
  // 是否存在漏洞
  pub vulnerable: bool,
  #[serde(flatten)]
  pub cpe_uri: CPEUri,
  // 包括 从版本开始
  pub version_start_including: Option<String>,
  // 排除 从版本开始
  pub version_start_excluding: Option<String>,
  // 包括 到版本结束
  pub version_end_including: Option<String>,
  // 排除 到版本结束
  pub version_end_excluding: Option<String>,
  #[serde(rename = "cpe_name")]
  pub cpe_name: Vec<CPEUri>,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CPEUri {
  ///  A CPE Match string is a single CPE Names string that correlates to one or many CPE Names in the Official CPE Dictionary. When a match string has the bug icon next to it, all matching CPE Names are considered vulnerable. You can click the caret below a CPE Match String to see the CPE Names in the dictionary that match.
  #[serde(
    serialize_with = "cpe::dictionary::attribute_to_uri",
    deserialize_with = "cpe::dictionary::uri_to_attribute"
  )]
  pub cpe23_uri: cpe::CPEName,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "UPPERCASE", deny_unknown_fields)]
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
  pub fn product(&self) -> cpe::Product {
    cpe::Product::from(&self.cpe_uri.cpe23_uri)
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
    if self.cpe_uri.cpe23_uri.match_product(product) {
      if self.has_version_range() {
        return self.match_version_range(version);
      }
      return self.cpe_uri.cpe23_uri.match_version(version);
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
  pub fn vendor_product(&self) -> HashSet<cpe::Product> {
    let product = self.cpe_match.iter().map(|m| m.product());
    let children = self.children.iter().flat_map(|node| node.vendor_product());
    product.chain(children).collect()
  }
}
