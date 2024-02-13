use std::str::FromStr;

use crate::modules::ListResponse;
use nvd_model::exploit::{Exploit, QueryExploit};
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::component::{EXPQuery, EXPQueryProps, EXPRow, ExpProps, Pagination, PaginationProps};
use crate::console_log;
use crate::routes::Route;
use crate::services::exp::exploit_list;
use crate::services::FetchState;

pub type ExploitInfoList = ListResponse<Exploit, QueryExploit>;

pub enum Msg {
  SetFetchState(FetchState<ExploitInfoList>),
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
  Query(QueryExploit),
  Source(String),
}

impl Component for ExploitInfoList {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let query = ctx
      .link()
      .location()
      .unwrap()
      .query::<QueryExploit>()
      .unwrap();
    ExploitInfoList {
      query,
      ..ExploitInfoList::default()
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
          match exploit_list(q).await {
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
          .push_with_query(&Route::Exp, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Send);
      }
      Msg::Query(query) => {
        match query {
          QueryMsg::Source(part) => {
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
          .push_with_query(&Route::Exp, &self.query)
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
            <thead>
              <tr>
                <th scope="col">{"Name"}</th>
                <th scope="col">{"Source"}</th>
                <th scope="col">{"Verified"}</th>
                <th scope="col">{"Path"}</th>
                <th scope="col">{"Meta"}</th>
                <th scope="col">{"Updated"}</th>
              </tr>
            </thead>
            <tbody>
            {
              self.result.iter().map(|item| {
              let p = ExpProps{props:item.clone()};
              html!{<>{html!( <EXPRow ..p/>) }</>}
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

impl ExploitInfoList {
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
      .callback(|args: QueryExploit| Msg::Query(QueryMsg::Query(args)));
    let p = EXPQueryProps {
      props: self.query.clone(),
      is_verified: None,
      query_source,
      query,
    };
    html! {
      <EXPQuery ..p.clone()/>
    }
  }
}
