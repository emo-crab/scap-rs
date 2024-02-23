mod attackerkb;
mod exploit_db;
mod github;
mod nuclei;
mod serde_format;

use std::fs::File;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};

use attackerkb_api_rs::pagination::KBResponse;
use attackerkb_api_rs::v1::query::TopicsParametersBuilder;
use attackerkb_api_rs::AttackKBApi;
use chrono::Utc;
use diesel::MysqlConnection;

use nvd_model::cve_knowledge_base::db::CreateCveKB;
use nvd_model::cve_knowledge_base::CveKnowledgeBase;
use nvd_model::error::DBResult;
use nvd_model::knowledge_base::db::{CreateKnowledgeBase, KBSource, KBTypes};
use nvd_model::knowledge_base::KnowledgeBase;
use nvd_model::types::{AnyValue, MetaData};

use crate::error::HelperResult;
use crate::kb::exploit_db::ExploitDB;
use crate::kb::github::GitHubCommit;
use crate::kb::nuclei::Template;
use crate::{init_db_pool, Connection};

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
            &new_kb,
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
              &new_exp,
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

pub async fn update_from_rss() {
  let connection_pool = init_db_pool();
  if let Ok(resp) = reqwest::get("https://www.exploit-db.com/rss.xml").await {
    let b = resp.bytes().await.unwrap_or_default();
    let s = String::from_utf8_lossy(&b);
    let rss: exploit_db::Rss = quick_xml::de::from_str(&s).unwrap();
    rss.update(connection_pool.get().unwrap().deref_mut()).await;
  }
}
