#![allow(clippy::large_enum_variant)]
use yew::prelude::*;

use nvd_model::knowledge_base::{KnowledgeBase, QueryKnowledgeBase};

use crate::component::{use_translation, KBRow, KbProps};
use crate::console_log;
use crate::modules::Paging;
use crate::services::kb::knowledge_base_list;
use crate::services::FetchState;

#[derive(Default)]
pub struct CVEKnowledgeBaseInfoList {
  pub result: Vec<KnowledgeBase>,
  pub paging: Paging,
  pub query: QueryKnowledgeBase,
}

#[derive(PartialEq, Clone, Properties)]
pub struct IDProps {
  pub id: String,
}

pub enum Msg {
  SetFetchState(FetchState<CVEKnowledgeBaseInfoList>),
  Send,
}

impl Component for CVEKnowledgeBaseInfoList {
  type Message = Msg;
  type Properties = IDProps;

  fn create(_ctx: &Context<Self>) -> Self {
    CVEKnowledgeBaseInfoList::default()
  }

  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::SetFetchState(state) => {
        match state {
          FetchState::Success(data) => {
            self.result = data.result;
            return true;
          }
          FetchState::Failed(err) => {
            console_log!("{:?}", err);
          }
        }
        return true;
      }
      Msg::Send => {
        let q = QueryKnowledgeBase {
          cve: Some(ctx.props().id.clone()),
          ..self.query.clone()
        };
        ctx.link().send_future(async move {
          match knowledge_base_list(q).await {
            Ok(data) => {
              let data = CVEKnowledgeBaseInfoList {
                result: data.result,
                paging: data.paging,
                query: data.query,
              };
              Msg::SetFetchState(FetchState::Success(data))
            }
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
    }
    false
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    let knowledge_base = self.result.clone();
    if !knowledge_base.is_empty() {
      return html! {
      <div class="table-responsive">
        <table class="table table-vcenter card-table table-striped">
          <KBHead/>
          <tbody>
          {knowledge_base.into_iter().map(|e|{
            let p = KbProps{props:e.clone()};
            html!{<KBRow ..p/>}
          }).collect::<Html>()}
          </tbody>
        </table>
      </div>
      };
    }
    html!()
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Send);
    }
  }
}
#[function_component]
pub fn KBHead() -> Html {
  let i18n = use_translation();
  html! {
    <thead>
      <tr>
        <th scope="col">{i18n.t("Name")}</th>
        <th scope="col">{i18n.t("Source")}</th>
        <th scope="col">{i18n.t("Verified")}</th>
        <th scope="col">{i18n.t("Path")}</th>
        <th scope="col">{i18n.t("Meta")}</th>
        <th scope="col">{i18n.t("Updated")}</th>
      </tr>
    </thead>
  }
}
