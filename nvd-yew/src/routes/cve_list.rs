use crate::component::CVERow;
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
  Query,
  GetError,
  NextPage,
  PrevPage,
  ToPage(i64),
  Severity(String),
  Vendor(String),
  Product(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct Props {
  pub query: QueryCve,
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
      Msg::Query => {
        let q = self.query.clone();
        // q.offset = Some(80);
        ctx.link().send_future(async {
          match cve_list(q).await {
            Ok(md) => Msg::SetFetchState(FetchState::Success(md)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
      Msg::GetError => {}
      Msg::NextPage => {
        self.query.offset = Some(self.query.offset.unwrap_or(0) + self.query.limit.unwrap_or(10));
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
      }
      Msg::PrevPage => {
        self.query.offset = Some(self.query.offset.unwrap_or(0) - self.query.limit.unwrap_or(10));
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
      }
      Msg::ToPage(page) => {
        self.query.offset = Some((page - 1) * self.query.limit.unwrap_or(10));
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
      }
      Msg::Severity(severity) => {
        self.query.severity = Some(severity);
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
      }
      Msg::Vendor(vendor) => {
        self.query.vendor = Some(vendor);
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
      }
      Msg::Product(product) => {
        self.query.product = Some(product);
        ctx
          .link()
          .navigator()
          .unwrap()
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Query);
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
      ctx.link().send_message(Msg::Query);
    }
  }
}

impl CveInfoList {
  fn pagination(&self, ctx: &Context<Self>) -> Html {
    let total = self.total;
    let limit = self.limit;
    let offset = self.offset;
    let next_page = ctx.link().callback(|_| Msg::NextPage);
    let prev_page = ctx.link().callback(|_| Msg::PrevPage);
    let to_page = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let page: i64 = i64::from_str(&target.clone().unchecked_into::<HtmlButtonElement>().value())
        .unwrap_or_default();
      Msg::ToPage(page)
    });
    let mut page_lists: Vec<(String, Vec<String>)> = Vec::new();
    let mut page_count = total / 10;
    if total % 10 != 0 {
      page_count = page_count + 1;
    }
    for n in (1..=page_count).into_iter() {
      let mut class_list = Vec::new();
      // 当前激活的页面
      let active = (offset / 10 + 1);
      if active == n {
        class_list.push("active".to_string());
      }
      // 前三个，后三个，激活页面三个
      if n <= 2 || n > page_count - 2 {
        page_lists.push((n.to_string(), class_list));
      } else if active == n {
        page_lists.push((n.to_string(), class_list));
      } else if n == active + 1 {
        page_lists.push((n.to_string(), class_list));
        if n < page_count - 2 {
          page_lists.push(("...".to_string(), vec!["disabled".to_string()]));
        }
      } else if n == active - 1 {
        // 离前三个很远
        if n > 3 {
          page_lists.push(("...".to_string(), vec!["disabled".to_string()]));
        }
        page_lists.push((n.to_string(), class_list));
      }
    }
    if !page_lists.contains(&("...".to_string(), vec!["disabled".to_string()])) && page_count > 6 {
      page_lists.insert(2, ("...".to_string(), vec!["disabled".to_string()]));
    }
    html! {
        <div class="card-footer d-flex align-items-center">
          <p class="m-0 text-muted">{"展示"} <span>{offset+1}</span> {"到"} <span>{offset+limit}</span> {"条"} <span>{"总数"}</span>{total} </p>
          <ul class="pagination pagination-sm m-0 ms-auto">
            <li class={classes!(["page-item",if offset == 0 { "disabled" } else { "" }])}>
              <button class="btn btn-sm page-link" onclick={prev_page}>
                {"prev"}
                <i class="bi bi-chevron-left"></i>
              </button>
            </li>
            {
              page_lists.into_iter().map(move|(n,active)|{
              html!{<li class={classes!(active)}><button class="page-link" onclick={to_page.clone()} value={n.to_string()}>{n}</button></li>}
            }).collect::<Html>()
            }
            <li class={classes!(["page-item",if offset+10>=total { "disabled" } else { "" }])}>
              <button class="btn btn-sm page-link" onclick={next_page}>
                {"next"}
                <i class="bi bi-chevron-right"></i>
              </button>
            </li>
          </ul>
        </div>
    }
  }
  fn query(&self, ctx: &Context<Self>) -> Html {
    let query_severity = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let severity: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      Msg::Severity(severity)
    });
    html! {
    <div class="card-body border-bottom py-1">
      <div class="d-flex">
        <div class="text-muted">
        <form class="row g-1">
          <div class="col input-group input-group-sm flex-nowrap">
          <ul class="dropdown">
            <button class="btn btn-dark btn-sm dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
              {"Severity"}
            </button>
            <ul class="dropdown-menu">
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-secondary btn-sm"  value="none">{"none (0.0)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-info btn-sm" value="low">{"low (0.1-3.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-warning btn-sm" value="medium">{"medium (4.0-6.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-danger btn-sm" value="high">{"high (7.0-8.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn text-light bg-dark btn-sm" value="critical">{"critical (9.0-10.0)"}</button></li>
            </ul>
          </ul>
          <input class="form-control form-control-sm" style="height: min-content;" value={self.query.severity.clone()}/>
          </div>
          <div class="col input-group input-group-sm text-muted" style="height: min-content;">
            <span class="input-group-text bg-info">{"Vendor"}</span>
            <input type="text" class="form-control"  aria-label="vendor"/>
          </div>
          <div class="col input-group input-group-sm text-muted" style="height: min-content;">
            <span class="input-group-text bg-success">{"Product"}</span>
            <input type="text" class="form-control"  aria-label="product"/>
          </div>
        </form>
        </div>
        <div class="ms-auto text-muted">
          <div class="input-group input-group-sm">
            <span class="input-group-text">{"Search"}</span>
            <input type="text" class="form-control form-control-sm" aria-label="Search invoice"/>
            <button class="btn btn-secondary" type="button"><i class="bi bi-search"></i></button>
          </div>
        </div>
      </div>
    </div>
    }
  }
}
