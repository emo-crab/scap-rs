//! ### Common Platform Enumeration (CPE): Dictionary
//! The Dictionary specification defines the concept of a CPE dictionary, which is a repository of CPE names and metadata, with each name identifying a single class of IT product. The Dictionary specification defines processes for using the dictionary, such as how to search for a particular CPE name or look for dictionary entries that belong to a broader product class. Also, the Dictionary specification outlines all the rules that dictionary maintainers must follow when creating new dictionary entries and updating existing entries.
//!
use crate::{parse_uri_attribute, CPEName};
use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
/// The cpe-list element acts as a top-level container for CPE Name items. Each individual item must be unique. Please refer to the description of ListType for additional information about the structure of this element.
///
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CPEList {
  pub generator: Generator,
  pub cpe_item: Vec<CPEItem>,
}
/**
The ItemType complex type defines an element that represents a single CPE
Name. The required name attribute is a URI which must be a unique key and should follow the URI
structure outlined in the CPE Specification. The optional title element is used to provide a
human-readable title for the platform. To support uses intended for multiple languages, this element
supports the ‘xml:lang’ attribute. At most one title element can appear for each language. The notes
element holds optional descriptive material. Multiple notes elements are allowed, but only one per
language should be used. Note that the language associated with the notes element applies to all child
note elements. The optional references element holds external info references. The optional check
element is used to call out an OVAL Definition that can confirm or reject an IT system as an instance of
the named platform. Additional elements not part of the CPE namespace are allowed and are just skipped
by validation. In essence, a dictionary file can contain additional information that a user can choose
to use or not, but this information is not required to be used or understood.
 */
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CPEItem {
  #[serde(rename(deserialize = "@name"), deserialize_with = "parse_name")]
  pub name: String,
  #[serde(default, rename(serialize = "deprecated", deserialize = "@deprecated"))]
  pub deprecated: bool,
  #[serde(
    default,
    rename(serialize = "deprecation_date", deserialize = "@deprecation_date"),
    skip_serializing_if = "Option::is_none"
  )]
  pub deprecation_date: Option<DateTime<Utc>>,
  #[serde(rename(serialize = "cpe23", deserialize = "cpe23-item"))]
  pub cpe23_item: CPE23Item,
  #[serde(default)]
  pub title: Vec<Title>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub notes: Option<Vec<Notes>>,
  pub references: Option<References>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub check: Option<Vec<Check>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Title {
  #[serde(rename(deserialize = "@lang"))]
  pub lang: String,
  #[serde(rename(deserialize = "$value"), deserialize_with = "parse_name")]
  pub value: String,
}
/**
The NotesType complex type defines an element that consists of one or more
child note elements. It is assumed that each of these note elements is representative of the same
language as defined by their parent.*/
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Notes {
  #[serde(rename(deserialize = "@lang"))]
  pub lang: String,
  #[serde(rename(deserialize = "$value"))]
  pub value: String,
}
/**
The CheckType complex type is used to define an element to hold information
about an individual check. It includes a checking system specification URI, string content, and an
optional external file reference. The checking system specification should be the URI for a particular
version of OVAL or a related system testing language, and the content will be an identifier of a test
written in that language. The external file reference could be used to point to the file in which the
content test identifier is defined.*/
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Check {
  pub system: String,
  pub href: Option<String>,
  #[serde(rename(deserialize = "$value"))]
  pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct References {
  pub reference: Vec<Reference>,
}
/**
The ReferencesType complex type defines an element used to hold a
collection of individual references. Each reference consists of a piece of text (intended to be
human-readable) and a URI (intended to be a URL, and point to a real resource) and is used to point to
extra descriptive material, for example a supplier's web site or platform
documentation.
 */
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Reference {
  #[serde(rename(deserialize = "@href"))]
  pub href: String,
  #[serde(rename(deserialize = "$value"))]
  pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CPE23Item {
  #[serde(
    rename(deserialize = "@name"),
    deserialize_with = "uri_to_attribute",
    serialize_with = "attribute_to_uri"
  )]
  pub name: CPEName,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub deprecation: Option<Deprecation>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Deprecation {
  #[serde(rename(deserialize = "@date"))]
  pub date: DateTime<Utc>,
  #[serde(rename(deserialize = "deprecated-by"))]
  pub deprecated_by: Vec<DeprecatedInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeprecatedInfo {
  #[serde(
    rename(deserialize = "@name"),
    deserialize_with = "uri_to_attribute",
    serialize_with = "attribute_to_uri"
  )]
  pub name: CPEName,
  #[serde(rename(deserialize = "@type"))]
  pub r#type: String,
}
/** The GeneratorType complex type defines an element that is used to hold
information about when a particular document was compiled, what version of the schema was used, what
tool compiled the document, and what version of that tool was used. Additional generator information is
also allowed although it is not part of the official schema. Individual organizations can place
generator information that they feel is important and it will be skipped during the validation. All that
this schema really cares about is that the stated generator information is there.*/
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Generator {
  /// The optional product_name element specifies the name of the application used to generate the file.
  pub product_name: String,
  /// The optional product_version element specifies the version of the application used to generate the file.
  pub product_version: String,
  /// The required schema_version element specifies the version of the schema that the document has been written against and that should be used for validation.
  pub schema_version: String,
  /** The required timestamp element specifies when the particular
  document was compiled. The format for the timestamp is yyyy-mm-ddThh:mm:ss. Note that the
  timestamp element does not specify when an item in the document was created or modified but
  rather when the actual XML document that contains the items was created. For example, a document
  might pull a bunch of existing items together, each of which was created at some point in the
  past. The timestamp in this case would be when this combined document was
  created.*/
  pub timestamp: DateTime<Utc>,
}

fn parse_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
  D: Deserializer<'de>,
{
  struct ParseString(PhantomData<CPEName>);
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

pub fn uri_to_attribute<'de, D>(deserializer: D) -> Result<CPEName, D::Error>
where
  D: Deserializer<'de>,
{
  struct UriToAttribute(PhantomData<CPEName>);
  impl<'de> de::Visitor<'de> for UriToAttribute {
    type Value = CPEName;
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
      match CPEName::from_str(value.as_str()) {
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

pub fn attribute_to_uri<S>(cpe: &CPEName, s: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  s.serialize_str(&cpe.to_string())
}
