use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use attackerkb_api_rs::AttackKBApi;
use attackerkb_api_rs::pagination::KBResponse;
use attackerkb_api_rs::v1::query::TopicsParametersBuilder;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use diesel::MysqlConnection;
use octocrab::{Octocrab, Page};
use octocrab::models::repos::{DiffEntryStatus, RepoCommit};
use reqwest::header;
use serde::{de, Deserialize, Deserializer, Serialize};

use nvd_model::cve_knowledge_base::CveKnowledgeBase;
use nvd_model::cve_knowledge_base::db::CreateCveKB;
use nvd_model::error::DBResult;
use nvd_model::knowledge_base::db::{CreateKnowledgeBase, KBSource, KBTypes};
use nvd_model::knowledge_base::KnowledgeBase;
use nvd_model::types::{AnyValue, MetaData};

use crate::{Connection, init_db_pool};
use crate::error::HelperResult;

mod date_format {
  use chrono::{NaiveDate, NaiveDateTime, Utc};
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub(crate) const FORMAT: &str = "%Y-%m-%d";

  pub fn serialize<S>(date: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: Serializer,
  {
    let s = date.to_string();
    serializer.serialize_str(&s)
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
    where
      D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
      return Ok(Utc::now().naive_local());
    }
    match NaiveDate::parse_from_str(&s, FORMAT) {
      Ok(naive_datetime) => Ok(
        naive_datetime
          .and_hms_opt(0, 0, 0)
          .unwrap_or(Utc::now().naive_local()),
      ),
      Err(err) => Err(serde::de::Error::custom(err)),
    }
  }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ExploitDB {
  id: u32,
  file: String,
  description: String,
  #[serde(with = "date_format")]
  date_published: NaiveDateTime,
  author: String,
  r#type: String,
  platform: String,
  port: Option<u16>,
  #[serde(with = "date_format")]
  date_added: NaiveDateTime,
  #[serde(with = "date_format")]
  date_updated: NaiveDateTime,
  verified: u8,
  codes: Option<String>,
  tags: Option<String>,
  aliases: Option<String>,
  screenshot_url: Option<String>,
  application_url: Option<String>,
  source_url: Option<String>,
}

impl ExploitDB {
  fn from_html(html: &str, item: &Item) -> Self {
    let id = item.link.rsplit_once('/').unwrap_or_default().1;
    let v = html.contains("<i class=\"mdi mdi-24px mdi-check\"");
    let mut exp = ExploitDB {
      id: id.parse().unwrap_or_default(),
      file: "".to_string(),
      description: item.description.clone(),
      date_published: item.published,
      author: "".to_string(),
      r#type: "".to_string(),
      platform: "".to_string(),
      port: None,
      date_added: Default::default(),
      date_updated: item.published,
      verified: v as u8,
      codes: None,
      tags: None,
      aliases: None,
      screenshot_url: None,
      application_url: None,
      source_url: None,
    };
    for line in html.lines() {
      if line.contains("<a href=\"https://nvd.nist.gov/vuln/detail/CVE-") {
        if let Some(u) = line.trim().trim_end_matches('"').strip_prefix("<a href=\"") {
          if let Some((_, id)) = u.rsplit_once('/') {
            exp.codes = Some(id.to_string());
          };
        };
      } else if line.contains("<a href=\"/?platform=") {
        if let Some(platform) = line
          .trim()
          .trim_end_matches("\">")
          .strip_prefix("<a href=\"/?platform=")
        {
          exp.platform = platform.to_string();
        };
      } else if line.contains("<a href=\"/?type=") {
        if let Some(t) = line
          .trim()
          .trim_end_matches("\">")
          .strip_prefix("<a href=\"/?type=")
        {
          exp.r#type = t.to_string();
        };
      } else if line.contains("<pre><code class=\"language-") {
        if let Some(u) = line
          .trim()
          .trim_end_matches('"')
          .strip_prefix("<pre><code class=\"language-")
        {
          if let Some((l, _)) = u.split_once('"') {
            exp.file = format!(
              "exploits/{}/{}/{}.{}",
              exp.platform,
              exp.r#type,
              id,
              l.to_lowercase()
            );
          };
        };
      }
    }
    exp
  }
}

pub fn create_or_update_exploit(
  connection: &mut MysqlConnection,
  kb_item: CreateKnowledgeBase,
  cve_id: Option<String>,
) -> DBResult<KnowledgeBase> {
  match KnowledgeBase::create_or_update(connection, &kb_item) {
    Ok(kb) => {
      if let Some(cve_id) = cve_id {
        let new_cve_exp = CreateCveKB {
          cve_id,
          knowledge_base_id: kb.id.clone(),
        };
        if let Err(err) = CveKnowledgeBase::create(connection, &new_cve_exp) {
          println!("漏洞利用关联CVE失败：{:?}", err);
        }
      }
      println!("从{}同步exploit: {}", kb_item.source, kb_item.path);
      Ok(kb)
    }
    Err(err) => Err(err),
  }
}

pub fn with_archive_exploit(path: PathBuf) {
  let file = File::open(path).unwrap();
  let mut rdr = csv::Reader::from_reader(file);
  let connection_pool = init_db_pool();
  for result in rdr.deserialize() {
    // Notice that we need to provide a type hint for automatic
    // deserialization.
    let kb_item: ExploitDB = result.unwrap();
    let meta = if let Some(code) = kb_item.codes {
      MetaData::from_hashset(
        "tags",
        code
          .split(';')
          .map(|s| s.to_string())
          .collect::<HashSet<String>>(),
      )
    } else {
      MetaData::default()
    };
    let new_exp = CreateKnowledgeBase {
      id: uuid::Uuid::new_v4().as_bytes().to_vec(),
      name: kb_item.id.to_string(),
      description: kb_item.description,
      source: KBSource::ExploitDb.to_string(),
      path: kb_item.file,
      meta: AnyValue::new(meta.clone()),
      verified: kb_item.verified,
      created_at: kb_item.date_published,
      updated_at: kb_item.date_updated,
      types: KBTypes::Exploit.to_string(),
    };
    if let Some(code_list) = meta.get_hashset("tags") {
      for c in code_list {
        if c.starts_with("CVE-") {
          // 是CVE
          if let Err(err) = create_or_update_exploit(
            connection_pool.get().unwrap().deref_mut(),
            new_exp.clone(),
            Some(c.clone()),
          ) {
            println!("是CVE： import knowledge_base err: {:?}", err);
          }
        } else {
          // code不为空，但是不是cve
          if let Err(err) = create_or_update_exploit(
            connection_pool.get().unwrap().deref_mut(),
            new_exp.clone(),
            None,
          ) {
            println!(
              "code不为空，但是不是cve： import knowledge_base err: {:?}",
              err
            );
          }
        }
      }
    } else {
      // code为空
      if let Err(err) = create_or_update_exploit(
        connection_pool.get().unwrap().deref_mut(),
        new_exp.clone(),
        None,
      ) {
        println!("code为空：import knowledge_base err: {:?}", err);
      }
    }
    // break;
  }
}

pub async fn update_from_github() {
  let connection_pool = init_db_pool();
  let commit_api = GitHubCommit::new("projectdiscovery", "nuclei-templates");
  commit_api
    .update(connection_pool.get().unwrap().deref_mut())
    .await;
}

/// 字符串转set
fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
  where
    D: Deserializer<'de>,
{
  struct StringToHashSet(PhantomData<HashSet<String>>);
  impl<'de> de::Visitor<'de> for StringToHashSet {
    type Value = HashSet<String>;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
      formatter.write_str("string or list of strings")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
    {
      let name: Vec<String> = value
        .split(',')
        .filter(|s| !s.starts_with("cve"))
        .map(String::from)
        .collect();
      Ok(HashSet::from_iter(name))
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

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct Template {
  id: String,
  info: Info,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct Info {
  name: String,
  description: String,
  classification: Option<Classification>,
  #[serde(deserialize_with = "string_to_hashset")]
  tags: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct Classification {
  #[serde(rename = "cve-id")]
  cve_id: Option<String>,
  cpe: Option<String>,
}

pub struct GitHubCommit {
  owner: String,
  repo: String,
  api: Arc<Octocrab>,
}

fn get_yaml_file(path: PathBuf) -> Vec<PathBuf> {
  let mut yaml_file_list: Vec<PathBuf> = Vec::new();
  if let Ok(read_dir) = Path::new(&path).read_dir() {
    for element in read_dir.filter_map(|res| res.ok()) {
      if element.path().is_dir() {
        yaml_file_list.extend(get_yaml_file(element.path()));
      }
      if element.path().is_file() {
        yaml_file_list.push(element.path());
      }
    }
  }
  yaml_file_list
}

pub fn import_from_nuclei_templates_path(path: PathBuf) {
  let mut connection_pool = init_db_pool().get().unwrap();
  let conn = connection_pool.deref_mut();
  let cve_path = path.join("http").join("cves");
  let yaml_paths = get_yaml_file(cve_path);
  for yaml_path in yaml_paths {
    if let Ok(f) = File::open(&yaml_path) {
      let template: Template = serde_yaml::from_reader(f).unwrap();
      let meta = MetaData::from_hashset("tags", template.info.tags);
      let new_exp = CreateKnowledgeBase {
        id: uuid::Uuid::new_v4().as_bytes().to_vec(),
        name: template.id.clone(),
        description: template.info.description,
        source: KBSource::NucleiTemplates.to_string(),
        path: yaml_path
          .strip_prefix(&path)
          .unwrap()
          .to_string_lossy()
          .to_string(),
        meta: AnyValue::new(meta),
        verified: 1,
        created_at: Utc::now().naive_utc(),
        updated_at: Utc::now().naive_utc(),
        types: KBTypes::Exploit.to_string(),
      };
      if let Err(err) = create_or_update_exploit(conn, new_exp, Some(template.id)) {
        println!("import nuclei knowledge_base err: {:?}", err);
      }
    }
  }
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
            let meta = MetaData::default();
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
                let new_exp = CreateKnowledgeBase {
                  id: uuid::Uuid::new_v4().as_bytes().to_vec(),
                  name: template.id.clone(),
                  description: template.info.description,
                  source: KBSource::NucleiTemplates.to_string(),
                  meta: AnyValue::new(meta),
                  verified: 1,
                  created_at: Utc::now().naive_utc(),
                  updated_at: Utc::now().naive_utc(),
                  path,
                  types: KBTypes::Exploit.to_string(),
                };
                if let Err(err) = create_or_update_exploit(conn, new_exp, Some(template.id)) {
                  println!("import nuclei knowledge_base err: {:?}", err);
                }
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

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
struct Rss {
  channel: Channel,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
struct Channel {
  item: Vec<Item>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
struct Item {
  title: String,
  link: String,
  description: String,
  #[serde(alias = "pubDate", deserialize_with = "rfc3339_deserialize")]
  published: NaiveDateTime,
}

pub fn rfc3339_deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
  where
    D: Deserializer<'de>,
{
  let s = String::deserialize(deserializer)?;
  if s.is_empty() {
    return Ok(Utc::now().naive_local());
  }
  match DateTime::parse_from_rfc2822(&s) {
    Ok(naive_datetime) => Ok(naive_datetime.naive_local()),
    Err(err) => Err(serde::de::Error::custom(err)),
  }
}

async fn get_info_from_exploit_url(conn: &mut Connection, item: &Item) {
  let mut headers = header::HeaderMap::new();
  let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";
  headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
  if let Ok(resp) = reqwest::ClientBuilder::new()
    .default_headers(headers)
    .build()
    .unwrap_or_default()
    .get(&item.link)
    .send()
    .await
  {
    let html = resp.text().await.unwrap_or_default();
    let kb_item = ExploitDB::from_html(&html, item);
    let meta = MetaData::default();
    let new_exp = CreateKnowledgeBase {
      id: uuid::Uuid::new_v4().as_bytes().to_vec(),
      name: kb_item.id.to_string(),
      description: kb_item.description,
      source: KBSource::ExploitDb.to_string(),
      path: kb_item.file,
      meta: AnyValue::new(meta.clone()),
      verified: kb_item.verified,
      created_at: kb_item.date_published,
      updated_at: kb_item.date_updated,
      types: KBTypes::Exploit.to_string(),
    };
    if !new_exp.path.is_empty()
      && kb_item.id != 0
      && !kb_item.r#type.is_empty()
      && !kb_item.platform.is_empty()
    {
      if let Err(err) = create_or_update_exploit(conn, new_exp, kb_item.codes) {
        println!("import nuclei knowledge_base err: {:?}", err);
      }
    }
  }
}

pub async fn update_from_rss() {
  let connection_pool = init_db_pool();
  if let Ok(resp) = reqwest::get("https://www.exploit-db.com/rss.xml").await {
    let b = resp.bytes().await.unwrap_or_default();
    let s = String::from_utf8_lossy(&b);
    let rss: Rss = quick_xml::de::from_str(&s).unwrap();
    for item in rss.channel.item {
      // 发布时间小于三天前跳过更新
      if item.published < (Utc::now() - Duration::days(3)).naive_utc() {
        continue;
      }
      get_info_from_exploit_url(connection_pool.get().unwrap().deref_mut(), &item).await;
    }
  }
}

// 绑定cve和exploit，也许是先有了exp，cve还没更新进来
pub fn associate_cve_and_exploit(conn: &mut Connection, id: &str) {
  // 查出有当前cve的exp，然后创建绑定关系
  if let Ok(kbs) = KnowledgeBase::query_by_cve(conn, id) {
    for kb in kbs {
      let new_cve_exp = CreateCveKB {
        cve_id: id.to_string(),
        knowledge_base_id: kb.id,
      };
      if let Err(err) = CveKnowledgeBase::create(conn, &new_cve_exp) {
        println!("漏洞利用关联CVE失败：{:?}", err);
      }
    }
  }
}

pub async fn akb_sync() -> HelperResult<()> {
  let token = if let Ok(t) = dotenvy::var("ABK_API_TOKEN") {
    Some(t)
  } else {
    None
  };
  if let Ok(api) = AttackKBApi::new(token) {
    let query = TopicsParametersBuilder::default()
      .q(Some("cve-2023-46805".into()))
      .build()
      .unwrap_or_default();
    let resp = api.topics(query).await;
    if let Ok(KBResponse::Topics(topics)) = resp {
      let connection_pool = init_db_pool();
      let meta = MetaData::default();
      for topic in topics.data {
        if topic.rapid7_analysis.is_some() {
          let new_kb = CreateKnowledgeBase {
            id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            name: topic.name.clone(),
            description: topic.document,
            source: KBSource::AttackerKB.to_string(),
            path: format!("https://attackerkb.com/topics/{}", topic.name),
            meta: AnyValue::new(meta),
            verified: true as u8,
            created_at: topic
              .rapid7_analysis_created
              .unwrap_or(Utc::now())
              .naive_utc(),
            updated_at: topic
              .rapid7_analysis_revision_date
              .unwrap_or(Utc::now())
              .naive_utc(),
            types: KBTypes::KnowledgeBase.to_string(),
          };
          if let Err(err) = create_or_update_exploit(
            connection_pool.get().unwrap().deref_mut(),
            new_kb,
            Some(topic.name),
          ) {
            println!("import attackerkb err: {:?}", err);
          }
          break;
        }
        if let Some(credits) = topic.metadata.credits {
          for module in credits.module {
            println!("同步metasploit插件：{}", module);
            let new_exp = CreateKnowledgeBase {
              id: uuid::Uuid::new_v4().as_bytes().to_vec(),
              name: topic.name.to_string(),
              description: topic.document.clone(),
              source: KBSource::Metasploit.to_string(),
              path: module,
              meta: AnyValue::new(meta.clone()),
              verified: true as u8,
              created_at: topic.created.naive_utc(),
              updated_at: topic.revision_date.naive_utc(),
              types: KBTypes::Exploit.to_string(),
            };
            if let Err(err) = create_or_update_exploit(
              connection_pool.get().unwrap().deref_mut(),
              new_exp,
              Some(topic.name.clone()),
            ) {
              println!("同步metasploit 插件失败： {:?}", err);
            };
          }
        }
      }
    }
  }
  Ok(())
}
