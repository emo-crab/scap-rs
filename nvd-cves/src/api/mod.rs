use crate::impact::ImpactMetrics;
use crate::v4::configurations::Node;
use crate::v4::{Description, Reference, Weaknesses};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CVE {
  pub id: String,
  pub source_identifier: String,
  pub published: NaiveDateTime,
  // 最后修改时间
  pub last_modified: NaiveDateTime,
  pub vuln_status: VulnStatus,
  pub descriptions: Vec<Description>,
  pub metrics: ImpactMetrics,
  #[serde(default)]
  pub weaknesses: Vec<Weaknesses>,
  #[serde(default)]
  pub configurations: Vec<Nodes>,
  pub references: Vec<Reference>,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Nodes {
  #[serde(default)]
  pub nodes: Vec<Node>,
}

// 漏洞状态，最新的有很多都是正在分析这个漏洞，没有什么数据，TODO： 可以在前端添加个过滤条件
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum VulnStatus {
  /// 已修改
  Modified,
  /// 已经分析
  Analyzed,
  /// 正在进行分析
  #[serde(rename = "Undergoing Analysis")]
  UndergoingAnalysis,
  /// 已拒绝
  Rejected,
  /// 被认可的
  Received,
  /// 等待分析
  #[serde(rename = "Awaiting Analysis")]
  AwaitingAnalysis,
}
