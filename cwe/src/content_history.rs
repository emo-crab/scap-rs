use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHistory {
  #[serde(rename(deserialize = "$value"))]
  pub references: Vec<ContentHistoryChild>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum ContentHistoryChild {
  #[serde(rename(deserialize = "Submission"))]
  Submission(Submission),
  #[serde(rename(deserialize = "Modification"))]
  Modification(Modification),
  #[serde(rename(deserialize = "Contribution"))]
  Contribution(Contribution),
  #[serde(rename(deserialize = "Previous_Entry_Name"))]
  PreviousEntryName {
    #[serde(rename(deserialize = "@Version"))]
    version: Option<String>,
    #[serde(rename(deserialize = "@Date"))]
    date: String,
    #[serde(rename(deserialize = "$value"))]
    previous_entry_name: String,
  },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
  #[serde(rename(deserialize = "Submission_Name"))]
  pub submission_name: Option<String>,
  #[serde(rename(deserialize = "Submission_Organization"))]
  pub submission_organization: Option<String>,
  #[serde(rename(deserialize = "Submission_Date"))]
  pub submission_date: String,
  #[serde(rename(deserialize = "Submission_Comment"))]
  pub submission_comment: Option<String>,
  #[serde(rename(deserialize = "Submission_Version"))]
  pub submission_version: String,
  #[serde(rename(deserialize = "Submission_ReleaseDate"))]
  pub submission_release_date: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Modification {
  #[serde(rename(deserialize = "Modification_Name"))]
  pub modification_name: Option<String>,
  #[serde(rename(deserialize = "Modification_Organization"))]
  pub modification_organization: Option<String>,
  #[serde(rename(deserialize = "Modification_Date"))]
  pub modification_date: String,
  #[serde(rename(deserialize = "Modification_Importance"))]
  pub modification_importance: Option<String>,
  #[serde(rename(deserialize = "Modification_Comment"))]
  pub modification_comment: Option<String>,
  #[serde(rename(deserialize = "Modification_Version"))]
  pub modification_version: Option<String>,
  #[serde(rename(deserialize = "Modification_ReleaseDate"))]
  pub modification_release_date: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
  #[serde(rename(deserialize = "@Type"))]
  pub r#type: Option<String>,
  #[serde(rename(deserialize = "Contribution_Name"))]
  pub contribution_name: Option<String>,
  #[serde(rename(deserialize = "Contribution_Organization"))]
  pub contribution_organization: Option<String>,
  #[serde(rename(deserialize = "Contribution_Date"))]
  pub contribution_date: String,
  #[serde(rename(deserialize = "Contribution_Comment"))]
  pub contribution_comment: Option<String>,
  #[serde(rename(deserialize = "Contribution_Version"))]
  pub contribution_version: Option<String>,
  #[serde(rename(deserialize = "Contribution_ReleaseDate"))]
  pub contribution_release_date: Option<String>,
}
