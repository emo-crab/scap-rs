use crate::kb::nuclei::Template;
use crate::Connection;
use chrono::{Duration, Utc};
use nvd_model::knowledge_base::db::KBSource;
use nvd_model::knowledge_base::KnowledgeBase;
use octocrab::models::repos::{DiffEntryStatus, RepoCommit};
use octocrab::{Octocrab, Page};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

pub struct GitHubCommit {
  owner: String,
  repo: String,
  api: Arc<Octocrab>,
}

impl GitHubCommit {
  pub fn new(owner: impl Into<String>, repo: impl Into<String>) -> Self {
    Self {
      owner: owner.into(),
      repo: repo.into(),
      api: octocrab::instance(),
    }
  }
  async fn get_commit_list(&self) -> octocrab::Result<Page<RepoCommit>> {
    let now = Utc::now();
    let three_hours = now - Duration::hours(3);
    println!(
      "开始更新从{}到{}kb",
      three_hours.to_rfc3339(),
      now.to_rfc3339()
    );
    self
      .api
      .repos(&self.owner, &self.repo)
      .list_commits()
      .path("http/cves")
      .since(three_hours)
      .send()
      .await
  }
  async fn get_commit(&self, sha: String) -> octocrab::Result<RepoCommit> {
    self.api.commits(&self.owner, &self.repo).get(sha).await
  }
  async fn get_template(&self, path: String) -> octocrab::Result<Template> {
    let content = self
      .api
      .repos(&self.owner, &self.repo)
      .get_content()
      .path(&path)
      .send()
      .await?;
    let mut code = String::new();
    for c in content.items {
      code.push_str(&c.decoded_content().unwrap_or_default())
    }
    let template: Template = serde_yaml::from_str(&code).unwrap_or_default();
    Ok(template)
  }

  pub async fn update(&self, conn: &mut Connection) {
    let list_commits = self.get_commit_list().await;
    let mut cache_map = HashSet::new();
    if let Ok(list_commits) = list_commits {
      for commits in list_commits {
        if let Ok(commit) = self.get_commit(commits.sha).await {
          for file in commit.files.clone().unwrap_or_default() {
            if cache_map.contains(&format!("{:?}_{}", file.status, file.filename)) {
              continue;
            }
            cache_map.insert(format!("{:?}_{}", file.status, file.filename));
            let path = file.filename.clone();
            let cve = Path::new(&file.filename)
              .file_name()
              .unwrap_or_default()
              .to_string_lossy()
              .to_string()
              .strip_suffix(&format!(
                ".{}",
                Path::new(&file.filename)
                  .extension()
                  .unwrap_or(OsStr::new(".yaml"))
                  .to_string_lossy()
                  .to_string()
                  .as_str()
              ))
              .unwrap_or_default()
              .to_string();
            if !cve.starts_with("CVE-") {
              break;
            }
            match file.status {
              DiffEntryStatus::Added | DiffEntryStatus::Modified => {
                let template = self.get_template(file.filename).await.unwrap_or_default();
                if !template.id.starts_with("CVE-") {
                  break;
                }
                template.update(conn, path);
              }
              DiffEntryStatus::Removed => {
                if let Err(err) = KnowledgeBase::delete(conn, &cve, KBSource::NucleiTemplates) {
                  println!("删除 knowledge_base err: {:?}", err);
                }
              }
              DiffEntryStatus::Renamed => {}
              DiffEntryStatus::Copied => {}
              DiffEntryStatus::Changed => {}
              DiffEntryStatus::Unchanged => {}
              _ => {}
            }
          }
        }
      }
    }
  }
}
