use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredCode {
    #[serde(rename = "@Nature")]
    pub nature: String,
    #[serde(rename = "@Language")]
    pub language: Option<String>,
    #[serde(rename = "$value", default)]
    pub children: Option<Vec<StructuredTextType>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredText {
    #[serde(rename = "$value")]
    pub descriptions: Vec<StructuredTextType>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StructuredTextType {
    #[serde(rename = "p")]
    P {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "b")]
    XhtmlB {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "ol")]
    XhtmlOl {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "li")]
    XhtmlLi {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "ul")]
    XhtmlUl {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "tbody")]
    XhtmlTBody {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "table")]
    XhtmlTable {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "tr")]
    XhtmlTr {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "th")]
    XhtmlTh {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "td")]
    XhtmlTd {
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "img")]
    XhtmlImg {
        #[serde(rename = "@src")]
        src: String,
        #[serde(rename = "@alt")]
        alt: Option<String>,
    },
    #[serde(rename = "div")]
    XhtmlDiv {
        #[serde(rename = "@style")]
        style: Option<String>,
        #[serde(rename = "$value", default)]
        children: Vec<Box<StructuredTextType>>,
    },
    #[serde(rename = "br")]
    XhtmlBr,
    #[serde(rename = "i")]
    XhtmlI {
        #[serde(rename = "$value")]
        text: String,
    },
    #[serde(rename = "$text")]
    Text(String),
}