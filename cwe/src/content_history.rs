use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHistory {
    #[serde(rename = "$value")]
    pub references: Vec<ContentHistoryChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ContentHistoryChild {
    #[serde(rename = "Submission")]
    Submission(Submission),
    #[serde(rename = "Modification")]
    Modification(Modification),
    #[serde(rename = "Contribution")]
    Contribution(Contribution),
    #[serde(rename = "Previous_Entry_Name")]
    PreviousEntryName {
        #[serde(rename = "@Date")]
        date: String,
        #[serde(rename = "$value")]
        previous_entry_name: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    #[serde(rename = "Submission_Name")]
    pub submission_name: Option<String>,
    #[serde(rename = "Submission_Organization")]
    pub submission_organization: Option<String>,
    #[serde(rename = "Submission_Date")]
    pub submission_date: String,
    #[serde(rename = "Submission_Comment")]
    pub submission_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Modification {
    #[serde(rename = "Modification_Name")]
    pub modification_name: Option<String>,
    #[serde(rename = "Modification_Organization")]
    pub modification_organization: Option<String>,
    #[serde(rename = "Modification_Date")]
    pub modification_date: String,
    #[serde(rename = "Modification_Importance")]
    pub modification_importance: Option<String>,
    #[serde(rename = "Modification_Comment")]
    pub modification_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    #[serde(rename = "@Type")]
    pub r#type: Option<String>,
    #[serde(rename = "Contribution_Name")]
    pub contribution_name: Option<String>,
    #[serde(rename = "Contribution_Organization")]
    pub contribution_organization: Option<String>,
    #[serde(rename = "Contribution_Date")]
    pub contribution_date: String,
    #[serde(rename = "Contribution_Comment")]
    pub contribution_comment: Option<String>,
}