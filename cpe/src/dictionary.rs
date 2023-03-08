use std::fmt;
use std::marker::PhantomData;
use serde::{de, Deserialize, Serialize, Deserializer};
use chrono::{DateTime, Utc};
use crate::{CpeAttributes, parse_uri_attribute};

// CpeList is The CpeList complex type defines an element that is used to hold a
//                 collection of individual items. The required generator section provides information about when the
//                 definition file was compiled and under what version. Additional elements not part of the CPE namespace
//                 are allowed and are just skipped by validation. In essence, a dictionary file can contain additional
//                 information that a user can choose to use or not, but this information is not required to be used or
//                 understood.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CpeList {
    pub generator: Generator,
    pub cpe_item: Vec<CpeItem>,
}

// CpeItem is The CpeItem complex type defines an element that represents a single CPE
//                 Name. The required name attribute is a URI which must be a unique key and should follow the URI
//                 structure outlined in the CPE Specification. The optional title element is used to provide a
//                 human-readable title for the platform. To support uses intended for multiple languages, this element
//                 supports the ‘xml:lang’ attribute. At most one title element can appear for each language. The notes
//                 element holds optional descriptive material. Multiple notes elements are allowed, but only one per
//                 language should be used. Note that the language associated with the notes element applies to all child
//                 note elements. The optional references element holds external info references. The optional check
//                 element is used to call out an OVAL Definition that can confirm or reject an IT system as an instance of
//                 the named platform. Additional elements not part of the CPE namespace are allowed and are just skipped
//                 by validation. In essence, a dictionary file can contain additional information that a user can choose
//                 to use or not, but this information is not required to be used or understood.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CpeItem {
    #[serde(rename(serialize = "name", deserialize = "@name"), deserialize_with = "parse_name")]
    pub name: String,
    #[serde(default, rename(serialize = "deprecated", deserialize = "@deprecated"), skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    #[serde(default, rename(serialize = "deprecation_date", deserialize = "@deprecation_date"), skip_serializing_if = "Option::is_none")]
    pub deprecation_date: Option<DateTime<Utc>>,
    #[serde(rename(serialize = "cpe23", deserialize = "cpe23-item"))]
    pub cpe23_item: Cpe23Item,
    pub title: Vec<Title>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<Notes>>,
    pub references: Option<References>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<Vec<Check>>,
}

// Title is The Title complex type allows the xml:lang attribute to associate a
//                 specific language with an element's string content.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Title {
    #[serde(rename(serialize = "lang", deserialize = "@lang"))]
    pub lang: String,
    #[serde(rename(serialize = "value", deserialize = "$value"), deserialize_with = "parse_name", )]
    pub desc: String,
}

// Notes is The Notes complex type defines an element that consists of one or more
//                 child note elements. It is assumed that each of these note elements is representative of the same
//                 language as defined by their parent.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Notes {
    #[serde(rename(serialize = "lang", deserialize = "@lang"))]
    pub lang: String,
    #[serde(rename(serialize = "value", deserialize = "$value"))]
    pub desc: String,
}

// Check is The Check complex type is used to define an element to hold information
//                 about an individual check. It includes a checking system specification URI, string content, and an
//                 optional external file reference. The checking system specification should be the URI for a particular
//                 version of OVAL or a related system testing language, and the content will be an identifier of a test
//                 written in that language. The external file reference could be used to point to the file in which the
//                 content test identifier is defined.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Check {
    #[serde(rename = "system")]
    pub system: String,
    #[serde(rename = "href")]
    pub href: Option<String>,
    #[serde(rename(serialize = "value", deserialize = "$value"))]
    pub value: String,
}

// References is The References complex type defines an element used to hold a
//                 collection of individual references. Each reference consists of a piece of text (intended to be
//                 human-readable) and a URI (intended to be a URL, and point to a real resource) and is used to point to
//                 extra descriptive material, for example a supplier's web site or platform
//                 documentation.
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

// Cpe23Item is The cpe-item element denotes a single CPE Name. Please refer to the
//                 description of ItemType for additional information about the structure of this
//                 element.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Cpe23Item {
    #[serde(rename(serialize = "name", deserialize = "@name"), deserialize_with = "uri_to_attribute")]
    pub name: CpeAttributes,
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
    #[serde(rename(serialize = "name", deserialize = "@name"), deserialize_with = "uri_to_attribute")]
    pub name: CpeAttributes,
    #[serde(rename(serialize = "type", deserialize = "@type"))]
    pub d_type: String,
}

// Generator is The required timestamp element specifies when the particular
//                         document was compiled. The format for the timestamp is yyyy-mm-ddThh:mm:ss. Note that the
//                         timestamp element does not specify when an item in the document was created or modified but
//                         rather when the actual XML document that contains the items was created. For example, a document
//                         might pull a bunch of existing items together, each of which was created at some point in the
//                         past. The timestamp in this case would be when this combined document was
//                         created.
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
    struct ParseString(PhantomData<CpeAttributes>);
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

fn uri_to_attribute<'de, D>(deserializer: D) -> Result<CpeAttributes, D::Error>
    where
        D: Deserializer<'de>,
{
    struct UriToAttribute(PhantomData<CpeAttributes>);
    impl<'de> de::Visitor<'de> for UriToAttribute {
        type Value = CpeAttributes;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("uri_to_attribute")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
        {
            // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
            let value = parse_uri_attribute(value).unwrap_or_default();
            match CpeAttributes::try_from(value.as_str()) {
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