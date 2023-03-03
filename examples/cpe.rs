use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::marker::PhantomData;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
struct CpeList {
    generator: Generator,
    cpe_item: Vec<CpeItem>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct CpeItem {
    #[serde(rename = "@name")]
    name: String,
    #[serde(default, rename = "@deprecated")]
    deprecated: Option<bool>,
    #[serde(default, rename = "@deprecation_date")]
    deprecation_date: Option<DateTime<Utc>>,
    #[serde(rename = "cpe23-item", deserialize_with = "uri_to_name")]
    cpe23_item: Cpe23Item,
    title: Vec<Title>,
    #[serde(default)]
    notes: HashMap<String, String>,
    references: Option<References>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Title {
    #[serde(rename = "@lang")]
    lang: String,
    #[serde(rename = "$value")]
    desc: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct References {
    reference: Vec<Reference>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Reference {
    #[serde(rename = "@href")]
    href: String,
    #[serde(rename = "$value")]
    desc: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
struct Cpe23Item {
    #[serde(rename = "@name", deserialize_with = "uri_to_attribute")]
    name: CpeAttributes,
    deprecation: Option<Deprecation>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
struct Deprecation {
    #[serde(rename = "@date")]
    date: DateTime<Utc>,
    #[serde(rename = "deprecated-by")]
    deprecated_by: Vec<DeprecatedInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct DeprecatedInfo {
    #[serde(rename = "@name", deserialize_with = "uri_to_attribute")]
    name: CpeAttributes,
    #[serde(rename = "@type")]
    d_type: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Generator {
    product_name: String,
    product_version: String,
    schema_version: String,
    timestamp: DateTime<Utc>,
}

fn uri_to_name<'de, D>(deserializer: D) -> Result<Cpe23Item, D::Error>
    where
        D: Deserializer<'de>,
{
    Cpe23Item::deserialize(deserializer)
}

fn uri_to_attribute<'de, D>(deserializer: D) -> Result<CpeAttributes, D::Error>
    where
        D: Deserializer<'de>,
{
    struct StringToHashSet(PhantomData<CpeAttributes>);
    impl<'de> de::Visitor<'de> for StringToHashSet {
        type Value = CpeAttributes;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
        {
            // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw: target_hw:other
            match CpeAttributes::try_from(value) {
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
    deserializer.deserialize_any(StringToHashSet(PhantomData))
}

fn strip_slashes(s: &str) -> String {
    let mut out = String::new();
    let mut chats = s.chars();
    while let Some(c) = chats.next() {
        if c == '\\' {
            if let Some(cc) = chats.next() {
                match cc {
                    '.' | '-' | '_' => {
                        continue;
                    }
                    _ => {}
                }
            }
        }
        out.push(c);
    }
    out
}

fn main() {
    let x = std::fs::read_to_string("/home/kali-team/IdeaProjects/nvd_rs/cpe.xml").unwrap();
    let c: CpeList = quick_xml::de::from_str(&x).unwrap();
    // println!("{:#?}", c);
    for cpe_item in c.cpe_item {
        println!("{:?}", cpe_item.name);
        println!("{:?}", cpe_item)
    }
}
// https://github.com/tafia/quick-xml/issues/429
