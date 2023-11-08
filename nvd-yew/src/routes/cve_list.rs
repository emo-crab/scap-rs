use crate::component::{CVEQuery, CVEQueryProps, CVERow, Pagination, PaginationProps};
use crate::console_log;
use crate::modules::cve::{CveInfoList, QueryCve};
use crate::routes::Route;
use crate::services::cve::cve_list;
use crate::services::FetchState;
use std::str::FromStr;
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;
use yew_router::prelude::*;
pub enum Msg {
  SetFetchState(FetchState<CveInfoList>),
  Send,
  GetError,
  PageMsg(PageMsg),
  QueryMsg(QueryMsg),
}
pub enum PageMsg {
  NextPage,
  PrevPage,
  ToPage(i64),
}
pub enum QueryMsg {
  Severity(String),
  Vendor(String),
  Product(String),
  Query(QueryCve),
}
impl Component for CveInfoList {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let query = ctx.link().location().unwrap().query::<QueryCve>().unwrap();
    CveInfoList {
      query,
      ..CveInfoList::default()
    }
  }
  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::SetFetchState(FetchState::Success(cil)) => {
        self.total = cil.total;
        self.offset = cil.offset;
        self.limit = cil.limit;
        self.result = cil.result;
        self.query.offset = Some(cil.offset);
        self.query.limit = Some(cil.limit);
        return true;
      }
      Msg::SetFetchState(FetchState::Failed(err)) => {
        console_log!("{}", err);
      }
      Msg::Send => {
        let q = self.query.clone();
        ctx.link().send_future(async {
          match cve_list(q).await {
            Ok(md) => Msg::SetFetchState(FetchState::Success(md)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
      Msg::GetError => {}
      Msg::PageMsg(page) => {
        match page {
          PageMsg::NextPage => {
            self.query.offset =
              Some(self.query.offset.unwrap_or(0) + self.query.limit.unwrap_or(10));
          }
          PageMsg::PrevPage => {
            self.query.offset =
              Some(self.query.offset.unwrap_or(0) - self.query.limit.unwrap_or(10));
          }
          PageMsg::ToPage(page) => {
            self.query.offset = Some((page - 1) * self.query.limit.unwrap_or(10));
          }
        }
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Send);
      }
      Msg::QueryMsg(query) => {
        match query {
          QueryMsg::Severity(severity) => {
            self.query.severity = Some(severity);
          }
          QueryMsg::Vendor(vendor) => {
            self.query.vendor = Some(vendor);
          }
          QueryMsg::Product(product) => {
            self.query.product = Some(product);
          }
          QueryMsg::Query(query) => {
            self.query = query;
          }
        }
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
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
          <table class="table card-table table-vcenter datatable table-striped table-sm">
            <thead>
              <tr>
                <th>{"CVE"}</th>
                <th>{"Vendors"}</th>
                <th>{"Products"}</th>
                <th>{"CWE"}</th>
                <th>{"CVSS v2"}</th>
                <th>{"CVSS v3"}</th>
                <th>{"Updated"}</th>
              </tr>
            </thead>
            <tbody>
            { self.result.iter().map(|item| {
              html!{<>{html!( <CVERow ..item.clone()/>) }</>}
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

impl CveInfoList {
  fn pagination(&self, ctx: &Context<Self>) -> Html {
    let total = self.total;
    let limit = self.limit;
    let offset = self.offset;
    let next_page = ctx.link().callback(|_| Msg::PageMsg(PageMsg::NextPage));
    let prev_page = ctx.link().callback(|_| Msg::PageMsg(PageMsg::PrevPage));
    let to_page = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let page: i64 = i64::from_str(&target.clone().unchecked_into::<HtmlButtonElement>().value())
        .unwrap_or_default();
      Msg::PageMsg(PageMsg::ToPage(page))
    });
    let p = PaginationProps {
      limit,
      total,
      offset,
      next_page,
      prev_page,
      to_page,
    };
    html! {<Pagination ..p.clone()/>}
  }
  fn query(&self, ctx: &Context<Self>) -> Html {
    let query_severity = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let severity: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      Msg::QueryMsg(QueryMsg::Severity(severity))
    });
    let query = ctx
      .link()
      .callback(|args:QueryCve| Msg::QueryMsg(QueryMsg::Query(args)));
    let p = CVEQueryProps {
      props: self.query.clone(),
      query_severity,
      query,
    };
    html! {
      <CVEQuery ..p.clone()/>
    }
  }
}
