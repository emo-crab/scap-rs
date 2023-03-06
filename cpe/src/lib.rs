// Package wfn provides a representation, bindings and matching of the Well-Formed CPE names as per
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf and
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

pub mod part;
pub mod component;

pub use part::CpePart;
pub use component::Component;

// view-source:https://csrc.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd
// https://scap.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct CpeAttributes {
    part: CpePart,
    vendor: Component,
    product: Component,
    version: Component,
    update: Component,
    edition: Component,
    language: Component,
    sw_edition: Component,
    target_sw: Component,
    target_hw: Component,
    other: Component,
}

impl TryFrom<&str> for CpeAttributes {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        CpeAttributes::from_str(val)
    }
}

impl FromStr for CpeAttributes {
    type Err = String;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let uri = match uri.strip_prefix("cpe:2.3:") {
            Some(u) => u,
            None => return Err("invalid prefix".to_string()),
        };

        let mut components = uri.split(':');

        let part = if let Some(part) = components.next() {
            CpePart::try_from(part)?
        } else {
            return Err("invalid part string".to_string());
        };
        let vendor = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid vendor string".to_string());
        };
        let product = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid product string".to_string());
        };
        let version = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid version string".to_string());
        };
        let update = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid update string".to_string());
        };
        let edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid edition string".to_string());
        };
        let language = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid language string".to_string());
        };
        let sw_edition = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid sw_edition string".to_string());
        };
        let target_sw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid target_sw string".to_string());
        };
        let target_hw = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid target_hw string".to_string());
        };
        let other = if let Some(part) = components.next() {
            Component::try_from(part)?
        } else {
            return Err("invalid other string".to_string());
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
            "cpe:2.3:{:#}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
            other
        )?;

        Ok(())
    }
}
