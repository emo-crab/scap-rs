use serde::Deserialize;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all="PascalCase")]
pub struct MappingNotes {
    pub usage: Usage,
    pub rationale:String,
    pub comments:String,
    pub reasons:Reasons,
    pub suggestions:Option<Suggestions>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestions{
    #[serde(rename = "Suggestion")]
    pub suggestion:Vec<Suggestion>
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestion{
    #[serde(rename = "@CWE_ID")]
    cwe_id:i32,
    #[serde(rename = "@Comment")]
    comment:String
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all="PascalCase")]
pub struct Reasons{
    pub reason:Reason,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason{
    #[serde(rename="@Type")]
    pub r#type: String,
}
#[derive(Debug, Deserialize)]
pub struct Usage{
    #[serde(rename="$text")]
    pub usage:UsageEnum
}

/// The UsageEnumeration simple type is used for whether this CWE entry is supported for mapping.
#[derive(Debug, Deserialize)]
pub enum UsageEnum{
    Discouraged,
    Prohibited,
    Allowed,
    #[serde(rename="Allowed-with-Review")]
    AllowedWithReview,
}
