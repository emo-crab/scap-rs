mod attackerkb;
mod exploit_db;
mod github;
mod nuclei;
mod serde_format;

use attackerkb_api_rs::v1::query::TopicsParametersBuilder;
use attackerkb_api_rs::AttackKBApi;
use chrono::{Duration, Utc};
use diesel::MysqlConnection;
use std::fs::File;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};

use crate::error::HelperResult;
use crate::kb::attackerkb::fetch_query;
use crate::kb::exploit_db::ExploitDB;
use crate::kb::github::GitHubCommit;
use crate::kb::nuclei::Template;
use crate::{init_db_pool, Connection};
use nvd_model::cve_knowledge_base::db::CreateCveKB;
use nvd_model::cve_knowledge_base::CveKnowledgeBase;
use nvd_model::error::DBResult;
use nvd_model::knowledge_base::db::CreateKnowledgeBase;
use nvd_model::knowledge_base::KnowledgeBase;

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

pub fn create_or_update_exploit(
  connection: &mut MysqlConnection,
  kb_item: &CreateKnowledgeBase,
  cve_id: Option<String>,
) -> DBResult<KnowledgeBase> {
  match KnowledgeBase::create_or_update(connection, kb_item) {
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

pub fn import_from_nuclei_templates_path(path: PathBuf) {
  let mut connection_pool = init_db_pool().get().unwrap();
  let conn = connection_pool.deref_mut();
  let cve_path = path.join("http").join("cves");
  let yaml_paths = get_yaml_file(cve_path);
  for yaml_path in yaml_paths {
    if let Ok(f) = File::open(&yaml_path) {
      let template: Template = serde_yaml::from_reader(f).unwrap();
      let mut new_exp: CreateKnowledgeBase = template.clone().into();
      new_exp.path = yaml_path
        .strip_prefix(&path)
        .unwrap()
        .to_string_lossy()
        .to_string();
      if let Err(err) = create_or_update_exploit(conn, &new_exp, Some(template.id)) {
        println!("import nuclei knowledge_base err: {:?}", err);
      }
    }
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
    kb_item.update(connection_pool.get().unwrap().deref_mut())
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

pub async fn akb_sync() -> HelperResult<()> {
  let token = if let Ok(t) = dotenvy::var("ABK_API_TOKEN") {
    Some(t)
  } else {
    None
  };
  if let Ok(api) = AttackKBApi::new(token) {
    let query = TopicsParametersBuilder::default()
      .rapid7_analysis_revised_after(Some((Utc::now() - Duration::days(3)).date_naive()))
      .build()
      .unwrap_or_default();
    fetch_query(api, query).await;
  }
  Ok(())
}

pub async fn update_from_rss() {
  let connection_pool = init_db_pool();
  if let Ok(resp) = reqwest::get("https://www.exploit-db.com/rss.xml").await {
    let b = resp.bytes().await.unwrap_or_default();
    let s = String::from_utf8_lossy(&b);
    let rss: exploit_db::Rss = quick_xml::de::from_str(&s).unwrap();
    rss.update(connection_pool.get().unwrap().deref_mut()).await;
  }
}
