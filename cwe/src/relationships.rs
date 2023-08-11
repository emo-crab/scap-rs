use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename = "Relationships")]
pub struct Relationships {
    #[serde(rename = "Has_Member", default)]
    pub has_members: Vec<HasMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Has_Member")]
pub struct HasMember {
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
    #[serde(rename = "@View_ID")]
    pub view_id: i64,
}