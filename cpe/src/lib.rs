// Package wfn provides a representation, bindings and matching of the Well-Formed CPE names as per
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf and
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};
use std::collections::HashSet;

pub mod part;
pub mod component;
pub mod dictionary;
pub mod error;

pub use part::CpePart;
pub use component::Component;
use crate::error::{CpeError, Result};

// view-source:https://csrc.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
// https://scap.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CpeAttributes {
    pub part: CpePart,
    pub vendor: Component,
    pub product: Component,
    pub version: Component,
    pub update: Component,
    pub edition: Component,
    pub language: Component,
    pub sw_edition: Component,
    pub target_sw: Component,
    pub target_hw: Component,
    pub other: Component,
}

impl CpeAttributes {
    pub fn from_uri(uri: &str) -> Result<Self> {
        let uri = match uri.strip_prefix("cpe:2.3:") {
            Some(u) => u,
            None => return Err(CpeError::InvalidPrefix { value: uri.to_string() }),
        };

        let mut components = uri.split(':');

        let part = if let Some(part) = components.next() {
            CpePart::try_from(part)?
        } else {
            return Err(CpeError::InvalidPart { value: uri.to_string() });
        };
        let vendor = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let product = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let version = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let update = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let language = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let sw_edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let target_sw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let target_hw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
        };
        let other = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err(CpeError::InvalidUri { value: uri.to_string() });
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
    pub fn from_wfn(name: &str) -> Result<Self> {
        let prefix = match name.strip_prefix("wfn:[") {
            Some(u) => u,
            None => return Err(CpeError::InvalidPrefix { value: name.to_string() }),
        };
        let components = match prefix.strip_suffix("]") {
            Some(u) => u,
            None => return Err(CpeError::InvalidPrefix { value: name.to_string() }),
        };
        let mut att = CpeAttributes {
            part: CpePart::default(),
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
                None => { return Err(CpeError::InvalidPart { value: component.to_string() }); }
                Some((k, v)) => {
                    match k {
                        "part" => { att.part = CpePart::try_from(v)? }
                        "vendor" => { att.vendor = Component::try_from(v)? }
                        "product" => { att.product = Component::try_from(v)? }
                        "version" => { att.version = Component::try_from(v)? }
                        "update" => { att.update = Component::try_from(v)? }
                        "edition" => { att.edition = Component::try_from(v)? }
                        "language" => { att.language = Component::try_from(v)? }
                        "sw_edition" => { att.sw_edition = Component::try_from(v)? }
                        "target_sw" => { att.target_sw = Component::try_from(v)? }
                        "target_hw" => { att.target_hw = Component::try_from(v)? }
                        "other" => { att.other = Component::try_from(v)? }
                        _ => {
                            return Err(CpeError::InvalidPart { value: k.to_string() });
                        }
                    }
                    // double
                    if !verify_set.remove(k) {
                        return Err(CpeError::InvalidPart { value: k.to_string() });
                    }
                }
            }
        }
        if !verify_set.is_empty() {
            return Err(CpeError::InvalidWfn { value: name.to_string() });
        }
        Ok(att)
    }
}

impl TryFrom<&str> for CpeAttributes {
    type Error = CpeError;
    fn try_from(val: &str) -> Result<Self> {
        CpeAttributes::from_str(val)
    }
}

impl FromStr for CpeAttributes {
    type Err = CpeError;
    fn from_str(uri: &str) -> Result<Self> {
        CpeAttributes::from_uri(uri)
    }
}

impl fmt::Display for CpeAttributes {
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
                    '\\' => { continue; }
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
            .map_err(|source| CpeError::Utf8Error {
                source,
                value: value.to_owned(),
            })?.to_string()
    } else {
        percent_encoding::percent_decode_str(&value)
            .decode_utf8()
            .map_err(|source| CpeError::Utf8Error {
                source,
                value: value.to_owned(),
            })?.to_string()
    };
    let value = strip_slashes(&value);
    Ok(value)
}