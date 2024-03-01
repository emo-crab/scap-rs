use crate::init_db_pool;
use crate::kb::create_or_update_exploit;
use attackerkb_api_rs::pagination::{KBResponse, ListResponse};
use attackerkb_api_rs::v1::query::TopicsParameters;
use attackerkb_api_rs::v1::topic::Topic;
use attackerkb_api_rs::AttackKBApi;
use chrono::Utc;
use nvd_model::knowledge_base::db::{CreateKnowledgeBase, KBSource, KBTypes};
use nvd_model::types::{AnyValue, MetaData};
use once_cell::sync::Lazy;
use regex::Regex;
use std::future::Future;
use std::ops::DerefMut;
use std::pin::Pin;

static RE_CVE: Lazy<Regex> =
  Lazy::new(|| -> Regex { Regex::new(r"(?m)\bCVE-\d{4}-\d{4,7}\b$").expect("RE_COMPILE_BY_CVE") });

fn is_cve(id: &str) -> bool {
  RE_CVE.is_match(id)
}

pub fn import_attackerkb(topics: &ListResponse<Topic>) {
  let connection_pool = init_db_pool();
  for topic in &topics.data {
    let meta = MetaData::default();
    if topic.rapid7_analysis.is_some() && is_cve(&topic.name) {
      let new_kb = CreateKnowledgeBase {
        id: uuid::Uuid::new_v4().as_bytes().to_vec(),
        name: topic.name.clone(),
        description: topic.document.clone(),
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
        Some(topic.name.clone()),
      ) {
        println!("import attackerkb err: {:?}", err);
      }
    } else {
      println!("不是CVE：{}", topic.name);
    }
    // if let Some(credits) = &topic.metadata.credits {
    //   for module in credits.module {
    //     println!("同步metasploit插件：{}", module);
    //     let new_exp = CreateKnowledgeBase {
    //       id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    //       name: topic.name.to_string(),
    //       description: topic.document.clone(),
    //       source: KBSource::Metasploit.to_string(),
    //       path: module,
    //       meta: AnyValue::new(meta.clone()),
    //       verified: true as u8,
    //       created_at: topic.created.naive_utc(),
    //       updated_at: topic.revision_date.naive_utc(),
    //       types: KBTypes::Exploit.to_string(),
    //     };
    //     if let Err(err) = create_or_update_exploit(
    //       connection_pool.get().unwrap().deref_mut(),
    //       &new_exp,
    //       Some(topic.name.clone()),
    //     ) {
    //       println!("同步metasploit 插件失败： {:?}", err);
    //     };
    //   }
    // }
  }
}

pub fn fetch_query(
  api: AttackKBApi,
  mut query: TopicsParameters,
) -> Pin<Box<dyn Future<Output = ()>>> {
  Box::pin(async move {
    let resp = api.topics(&query).await;
    match resp {
      Ok(KBResponse::Topics(topics)) => {
        import_attackerkb(&topics);
        if let Some(link) = topics.links {
          if link.next.is_some() {
            query.page += 1;
            fetch_query(api, query).await;
          }
        }
      }
      Err(err) => {
        println!("请求失败: {:?}", err);
      }
      _ => {
        println!("未知：{:?}", resp)
      }
    }
  })
}
