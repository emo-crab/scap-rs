use serde::{Deserialize,Serialize};
#[derive(Debug, Deserialize,Serialize)]
#[serde(deny_unknown_fields, rename_all="PascalCase")]
pub struct MappingNotes {
    pub usage: Usage,
    pub rationale:String,
    pub comments:String,
    pub reasons:Reasons,
    pub suggestions:Option<Suggestions>,
}
#[derive(Debug, Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestions{
    #[serde(rename(deserialize = "Suggestion"))]
    pub suggestion:Vec<Suggestion>
}
#[derive(Debug, Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestion{
    #[serde(rename(deserialize = "@CWE_ID"))]
    pub cwe_id:i32,
    #[serde(rename(deserialize = "@Comment"))]
    pub comment:String
}
#[derive(Debug, Deserialize,Serialize)]
#[serde(deny_unknown_fields, rename_all="PascalCase")]
pub struct Reasons{
    pub reason:Reason,
}
#[derive(Debug, Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reason{
    #[serde(rename="@Type")]
    pub r#type: String,
}
#[derive(Debug, Deserialize,Serialize)]
pub struct Usage{
    #[serde(rename="$text")]
    pub usage:UsageEnum
}

/// The UsageEnumeration simple type is used for whether this CWE entry is supported for mapping.
#[derive(Debug, Deserialize,Serialize)]
pub enum UsageEnum{
    Discouraged,
    Prohibited,
    Allowed,
    #[serde(rename="Allowed-with-Review")]
    AllowedWithReview,
}
