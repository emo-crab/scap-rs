use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredCode {
  #[serde(rename(deserialize = "@Nature"))]
  pub nature: String,
  #[serde(rename(deserialize = "@Language"))]
  pub language: Option<String>,
  #[serde(rename(deserialize = "$value"), default)]
  pub children: Option<Vec<StructuredTextType>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredText {
  #[serde(rename(deserialize = "$value"))]
  pub descriptions: Vec<StructuredTextType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum StructuredTextType {
  #[serde(rename(deserialize = "p"))]
  P {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "sup"))]
  Sup {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "b"))]
  XhtmlB {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "ol"))]
  XhtmlOl {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "li"))]
  XhtmlLi {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "ul"))]
  XhtmlUl {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "tbody"))]
  XhtmlTBody {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "table"))]
  XhtmlTable {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "tr"))]
  XhtmlTr {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "th"))]
  XhtmlTh {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "td"))]
  XhtmlTd {
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "img"))]
  XhtmlImg {
    #[serde(rename(deserialize = "@src"))]
    src: String,
    #[serde(rename(deserialize = "@alt"))]
    alt: Option<String>,
  },
  #[serde(rename(deserialize = "div"))]
  XhtmlDiv {
    #[serde(rename(deserialize = "@style"))]
    style: Option<String>,
    #[serde(rename(deserialize = "$value"), default)]
    children: Vec<Box<StructuredTextType>>,
  },
  #[serde(rename(deserialize = "br"))]
  XhtmlBr,
  #[serde(rename(deserialize = "i"))]
  XhtmlI {
    #[serde(rename(deserialize = "$value"))]
    text: String,
  },
  #[serde(rename(deserialize = "$text"))]
  Text(String),
}
