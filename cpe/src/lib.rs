// Package wfn provides a representation, bindings and matching of the Well-Formed CPE names as per
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf and
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{convert::TryFrom, fmt, str::FromStr};

pub mod component;
pub mod dictionary;
pub mod error;
pub mod part;

use crate::component::Language;
use crate::error::{CPEError, Result};
pub use component::Component;
pub use part::CPEPart;

// view-source:https://csrc.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
// https://scap.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
// CPE属性
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct CPEAttributes {
  // 分类：a，o，h
  pub part: CPEPart,
  // 创建产品个人或者组织/厂商
  pub vendor: Component,
  // 产品标题或者名称
  pub product: Component,
  // 由厂商提供用来表示产品的特定的发行版本
  pub version: Component,
  // 同样是厂商提供表示产品的更新版本，比version范围更小
  pub update: Component,
  // 这个属性同样表示版本，属于被弃用的属性，一般是为了兼容更早CPE版本，默认值为ANY
  pub edition: Component,
  // 表示产品在操作界面所支持的语言
  pub language: Language,
  // 表示产品是针对某些特定市场或类别的目标用户
  pub sw_edition: Component,
  // 产品运行需要的软件环境
  pub target_sw: Component,
  // 产品运行需要的硬件环境
  pub target_hw: Component,
  // 表示无法归类上上述其他属性的值
  pub other: Component,
}

impl CPEAttributes {
  // 从uri转CPE属性
  pub fn from_uri(uri: &str) -> Result<Self> {
    let uri = match uri.strip_prefix("cpe:2.3:") {
      Some(u) => u,
      None => {
        return Err(CPEError::InvalidPrefix {
          value: uri.to_string(),
        });
      }
    };

    let mut components = uri.split(':');

    let part = if let Some(part) = components.next() {
      CPEPart::try_from(part)?
    } else {
      return Err(CPEError::InvalidPart {
        value: uri.to_string(),
      });
    };
    let vendor = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let product = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let version = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let update = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let edition = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let language = if let Some(part) = components.next() {
      Language::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let sw_edition = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let target_sw = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let target_hw = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };
    let other = if let Some(part) = components.next() {
      Component::try_from(part)?
    } else {
      return Err(CPEError::InvalidUri {
        value: uri.to_string(),
      });
    };

    Ok(Self {
      part,
      vendor,
      product,
      version,
      update,
      edition,
      language,
      sw_edition,
      target_sw,
      target_hw,
      other,
    })
  }
  // 从wfn转CPE属性
  pub fn from_wfn(name: &str) -> Result<Self> {
    let prefix = match name.strip_prefix("wfn:[") {
      Some(u) => u,
      None => {
        return Err(CPEError::InvalidPrefix {
          value: name.to_string(),
        });
      }
    };
    let components = match prefix.strip_suffix(']') {
      Some(u) => u,
      None => {
        return Err(CPEError::InvalidPrefix {
          value: name.to_string(),
        });
      }
    };
    let mut att = CPEAttributes {
      part: CPEPart::default(),
      vendor: Default::default(),
      product: Default::default(),
      version: Default::default(),
      update: Default::default(),
      edition: Default::default(),
      language: Default::default(),
      sw_edition: Default::default(),
      target_sw: Default::default(),
      target_hw: Default::default(),
      other: Default::default(),
    };
    let mut verify_set = HashSet::from([
      "part",
      "vendor",
      "product",
      "version",
      "update",
      "edition",
      "language",
      "sw_edition",
      "target_sw",
      "target_hw",
      "other",
    ]);
    for component in components.split(',') {
      match component.split_once('=') {
        None => {
          return Err(CPEError::InvalidPart {
            value: component.to_string(),
          });
        }
        Some((k, v)) => {
          match k {
            "part" => att.part = CPEPart::try_from(v)?,
            "vendor" => att.vendor = Component::try_from(v)?,
            "product" => att.product = Component::try_from(v)?,
            "version" => att.version = Component::try_from(v)?,
            "update" => att.update = Component::try_from(v)?,
            "edition" => att.edition = Component::try_from(v)?,
            "language" => att.language = Language::try_from(v)?,
            "sw_edition" => att.sw_edition = Component::try_from(v)?,
            "target_sw" => att.target_sw = Component::try_from(v)?,
            "target_hw" => att.target_hw = Component::try_from(v)?,
            "other" => att.other = Component::try_from(v)?,
            _ => {
              return Err(CPEError::InvalidPart {
                value: k.to_string(),
              });
            }
          }
          // double
          if !verify_set.remove(k) {
            return Err(CPEError::InvalidPart {
              value: k.to_string(),
            });
          }
        }
      }
    }
    if !verify_set.is_empty() {
      return Err(CPEError::InvalidWfn {
        value: name.to_string(),
      });
    }
    Ok(att)
  }
}

impl TryFrom<&str> for CPEAttributes {
  type Error = CPEError;
  fn try_from(val: &str) -> Result<Self> {
    CPEAttributes::from_str(val)
  }
}

impl FromStr for CPEAttributes {
  type Err = CPEError;
  fn from_str(uri: &str) -> Result<Self> {
    CPEAttributes::from_uri(uri)
  }
}

impl fmt::Display for CPEAttributes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Self {
      part,
      vendor,
      product,
      version,
      update,
      edition,
      language,
      sw_edition,
      target_sw,
      target_hw,
      other,
    } = self;

    write!(
            f,
            "cpe:2.3:{part:#}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}",
        )
  }
}

fn strip_slashes(s: &str) -> String {
  let mut out = String::new();
  let mut chats = s.chars();
  while let Some(c) = chats.next() {
    if c == '\\' {
      if let Some(cc) = chats.next() {
        match cc {
          '\\' => {
            continue;
          }
          _ => {
            out.push(cc);
          }
        }
      }
    } else {
      out.push(c);
    }
  }
  out
}

fn parse_uri_attribute(value: &str) -> Result<String> {
  let value = if value.contains("%01") || value.contains("%02") {
    let value = value.replace("%01", "?").replace("%02", "*");
    percent_encoding::percent_decode_str(&value)
      .decode_utf8()
      .map_err(|source| CPEError::Utf8Error {
        source,
        value: value.to_owned(),
      })?
      .to_string()
  } else {
    percent_encoding::percent_decode_str(value)
      .decode_utf8()
      .map_err(|source| CPEError::Utf8Error {
        source,
        value: value.to_owned(),
      })?
      .to_string()
  };
  let value = strip_slashes(value.as_str());
  Ok(value)
}

pub fn version_cmp(a: &str, b: &str, operator: &str) -> bool {
  if let Ok(op) = version_compare::Cmp::from_sign(operator) {
    if let Ok(res) = version_compare::compare_to(a, b, op) {
      return res;
    }
  }
  false
}

impl CPEAttributes {
  // 匹配指定版本是否存在漏洞
  pub fn match_version(&self, version: &str) -> bool {
    if self.version.is_any() {
      return true;
    } else if self.version.is_na() {
      return false;
    }
    let my_version = if self.update.is_value() {
      format!("{} {}", self.version, self.update)
    } else {
      self.version.to_string()
    };
    version_cmp(version, &my_version, "==")
  }
  // 是否匹配指定产品
  pub fn match_product(&self, product: &str) -> bool {
    if self.product.is_any() {
      return true;
    } else if self.product.is_na() {
      return false;
    }
    product == self.normalize_target_software()
  }
  // 规范化目标软件,
  fn normalize_target_software(&self) -> String {
    if let Component::Value(software) = &self.target_sw {
      format!("{}-{}", software, self.product)
    } else {
      self.product.to_string()
    }
  }
}
