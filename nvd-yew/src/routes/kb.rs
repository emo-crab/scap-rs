use std::str::FromStr;

use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;
use yew_router::prelude::*;

use nvd_model::knowledge_base::{KnowledgeBase, QueryKnowledgeBase};

use crate::component::{
  use_translation, KBQuery, KBQueryProps, KBRow, KbProps, Pagination, PaginationProps,
};
use crate::console_log;
use crate::modules::ListResponse;
use crate::routes::Route;
use crate::services::kb::knowledge_base_list;
use crate::services::FetchState;

pub type KnowledgeBaseInfoList = ListResponse<KnowledgeBase, QueryKnowledgeBase>;

pub enum Msg {
  SetFetchState(FetchState<KnowledgeBaseInfoList>),
  Send,
  Page(PageMsg),
  Query(QueryMsg),
}

pub enum PageMsg {
  Next,
  Prev,
  To(i64),
}

pub enum QueryMsg {
  Query(QueryKnowledgeBase),
  Source(String),
}

impl Component for KnowledgeBaseInfoList {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let query = ctx
      .link()
      .location()
      .unwrap()
      .query::<QueryKnowledgeBase>()
      .unwrap();
    KnowledgeBaseInfoList {
      query,
      ..KnowledgeBaseInfoList::default()
    }
  }
  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::SetFetchState(FetchState::Success(cil)) => {
        self.query.page = Some(cil.paging.page);
        self.query.size = Some(cil.paging.size);
        self.paging = cil.paging;
        self.result = cil.result;
        return true;
      }
      Msg::SetFetchState(FetchState::Failed(err)) => {
        console_log!("{}", err);
      }
      Msg::Send => {
        let q = self.query.clone();
        ctx.link().send_future(async {
          match knowledge_base_list(q).await {
            Ok(data) => Msg::SetFetchState(FetchState::Success(data)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
      Msg::Page(page) => {
        match page {
          PageMsg::Next => {
            self.query.page = Some(self.query.page.unwrap_or(0) + 1);
          }
          PageMsg::Prev => {
            self.query.page = Some(self.query.page.unwrap_or(0) - 1);
          }
          PageMsg::To(page) => {
            self.query.page = Some(page - 1);
          }
        }
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::Kb, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Send);
      }
      Msg::Query(query) => {
        match query {
          QueryMsg::Source(part) => {
            self.paging.page = 0;
            self.query.source = Some(part);
          }
          QueryMsg::Query(query) => {
            self.query = query;
          }
        }
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::Kb, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Send);
      }
    }
    false
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    html! {
      <div class="card">
        {self.query(ctx)}
        <div class="table-responsive">
          <table class="table card-table table-vcenter table-striped table-sm table-hover">
            <KBHead/>
            <tbody>
            {
              self.result.iter().map(|item| {
              let p = KbProps{props:item.clone()};
              html!{<>{html!( <KBRow ..p/>) }</>}
                }).collect::<Html>()
              }
            </tbody>
          </table>
        </div>
      {self.pagination(ctx)}
      </div>
    }
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Send);
    }
  }
}

impl KnowledgeBaseInfoList {
  fn pagination(&self, ctx: &Context<Self>) -> Html {
    let paging = self.paging.clone();
    let next_page = ctx.link().callback(|_| Msg::Page(PageMsg::Next));
    let prev_page = ctx.link().callback(|_| Msg::Page(PageMsg::Prev));
    let to_page = ctx.link().callback(|event: MouseEvent| {
      let target: EventTarget = event.target().unwrap();
      let page: i64 = i64::from_str(&target.clone().unchecked_into::<HtmlButtonElement>().value())
        .unwrap_or_default();
      Msg::Page(PageMsg::To(page))
    });
    let p = PaginationProps {
      paging,
      next_page,
      prev_page,
      to_page,
    };
    html! {<Pagination ..p.clone()/>}
  }
  fn query(&self, ctx: &Context<Self>) -> Html {
    let query_source = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let severity: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      Msg::Query(QueryMsg::Source(severity))
    });
    let query = ctx
      .link()
      .callback(|args: QueryKnowledgeBase| Msg::Query(QueryMsg::Query(args)));
    let p = KBQueryProps {
      props: self.query.clone(),
      is_verified: None,
      query_source,
      query,
    };
    html! {
      <KBQuery ..p.clone()/>
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
