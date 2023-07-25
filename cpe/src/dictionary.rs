use crate::{parse_uri_attribute, CPEAttributes};
use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CPEList {
  pub generator: Generator,
  pub cpe_item: Vec<CPEItem>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CPEItem {
  #[serde(
    rename(serialize = "name", deserialize = "@name"),
    deserialize_with = "parse_name"
  )]
  pub name: String,
  #[serde(
    default,
    rename(serialize = "deprecated", deserialize = "@deprecated"),
    skip_serializing_if = "Option::is_none"
  )]
  pub deprecated: Option<bool>,
  #[serde(
    default,
    rename(serialize = "deprecation_date", deserialize = "@deprecation_date"),
    skip_serializing_if = "Option::is_none"
  )]
  pub deprecation_date: Option<DateTime<Utc>>,
  #[serde(rename(serialize = "cpe23", deserialize = "cpe23-item"))]
  pub cpe23_item: CPE23Item,
  pub title: Vec<Title>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub notes: Option<Vec<Notes>>,
  pub references: Option<References>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub check: Option<Vec<Check>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Title {
  #[serde(rename(serialize = "lang", deserialize = "@lang"))]
  pub lang: String,
  #[serde(
    rename(serialize = "value", deserialize = "$value"),
    deserialize_with = "parse_name"
  )]
  pub desc: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Notes {
  #[serde(rename(serialize = "lang", deserialize = "@lang"))]
  pub lang: String,
  #[serde(rename(serialize = "value", deserialize = "$value"))]
  pub desc: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Check {
  #[serde(rename = "system")]
  pub system: String,
  #[serde(rename = "href")]
  pub href: Option<String>,
  #[serde(rename(serialize = "value", deserialize = "$value"))]
  pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct References {
  reference: Vec<Reference>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Reference {
  #[serde(rename(serialize = "href", deserialize = "@href"))]
  pub href: String,
  #[serde(rename(serialize = "value", deserialize = "$value"))]
  pub desc: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CPE23Item {
  #[serde(
    rename(serialize = "name", deserialize = "@name"),
    deserialize_with = "uri_to_attribute"
  )]
  pub name: CPEAttributes,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub deprecation: Option<Deprecation>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct Deprecation {
  #[serde(rename(serialize = "date", deserialize = "@date"))]
  pub date: DateTime<Utc>,
  #[serde(rename = "deprecated-by")]
  pub deprecated_by: Vec<DeprecatedInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DeprecatedInfo {
  #[serde(
    rename(serialize = "name", deserialize = "@name"),
    deserialize_with = "uri_to_attribute"
  )]
  pub name: CPEAttributes,
  #[serde(rename(serialize = "type", deserialize = "@type"))]
  pub d_type: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Generator {
  pub product_name: String,
  pub product_version: String,
  pub schema_version: String,
  pub timestamp: DateTime<Utc>,
}

fn parse_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
  D: Deserializer<'de>,
{
  struct ParseString(PhantomData<CPEAttributes>);
  impl<'de> de::Visitor<'de> for ParseString {
    type Value = String;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
      formatter.write_str("parse_name")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
      E: de::Error,
    {
      // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
      match parse_uri_attribute(value) {
        Ok(p) => Ok(p),
        Err(e) => Err(de::Error::custom(e)),
      }
    }
    fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
    where
      S: de::SeqAccess<'de>,
    {
      Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
    }
  }
  deserializer.deserialize_any(ParseString(PhantomData))
}

pub fn uri_to_attribute<'de, D>(deserializer: D) -> Result<CPEAttributes, D::Error>
where
  D: Deserializer<'de>,
{
  struct UriToAttribute(PhantomData<CPEAttributes>);
  impl<'de> de::Visitor<'de> for UriToAttribute {
    type Value = CPEAttributes;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
      formatter.write_str("uri_to_attribute")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
      E: de::Error,
    {
      // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
      // https://cpe.mitre.org/specification/#downloads
      let value = parse_uri_attribute(value).unwrap_or_default();
      match CPEAttributes::try_from(value.as_str()) {
        Ok(p) => Ok(p),
        Err(e) => Err(de::Error::custom(e)),
      }
    }
    fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
    where
      S: de::SeqAccess<'de>,
    {
      Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
    }
  }
  deserializer.deserialize_any(UriToAttribute(PhantomData))
}
