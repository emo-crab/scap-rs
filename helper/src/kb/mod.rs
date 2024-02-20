use std::ops::DerefMut;

use attackerkb_api_rs::pagination::KBResponse;
use attackerkb_api_rs::v1::query::TopicsParametersBuilder;
use attackerkb_api_rs::AttackKBApi;
use chrono::Utc;
use diesel::MysqlConnection;

use nvd_model::error::DBResult;
use nvd_model::knowledge_base::db::{CreateKnowledgeBase, KnowledgeBaseSource};
use nvd_model::knowledge_base::KnowledgeBase;
use nvd_model::types::{AnyValue, MetaData};

use crate::error::HelperResult;
use crate::init_db_pool;

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
          let new_exp = CreateKnowledgeBase {
            id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            name: topic.name.clone(),
            description: topic.document,
            source: KnowledgeBaseSource::AttackerKB.to_string(),
            links: format!("https://attackerkb.com/topics/{}", topic.name),
            meta: AnyValue::new(meta),
            created_at: topic
              .rapid7_analysis_created
              .unwrap_or(Utc::now())
              .naive_local(),
            updated_at: topic
              .rapid7_analysis_revision_date
              .unwrap_or(Utc::now())
              .naive_local(),
          };
          if let Err(err) = create_or_update_kb(connection_pool.get().unwrap().deref_mut(), new_exp)
          {
            println!("import attackerkb err: {:?}", err);
          }
          break;
        }
      }
    }
  }
  Ok(())
}

fn create_or_update_kb(
  connection: &mut MysqlConnection,
  kb_item: CreateKnowledgeBase,
) -> DBResult<KnowledgeBase> {
  match KnowledgeBase::create_or_update(connection, &kb_item) {
    Ok(kb) => {
      println!("从{}同步kb: {}", kb_item.source, kb_item.links);
      Ok(kb)
    }
    Err(err) => Err(err),
  }
}
