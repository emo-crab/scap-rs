use std::str::FromStr;

use nvd_model::cve::{Cve, QueryCve};
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::component::{
  use_translation, CVEQuery, CVEQueryProps, CVERow, CveProps, Pagination, PaginationProps,
};
use crate::console_log;
use crate::modules::ListResponse;
use crate::routes::Route;
use crate::services::cve::cve_list;
use crate::services::FetchState;

pub type CveInfoList = ListResponse<Cve, QueryCve>;
pub enum Msg {
  SetFetchState(FetchState<CveInfoList>),
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
  Severity(String),
  Vendor(String),
  Product(String, String),
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
          match cve_list(q).await {
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
          .push_with_query(&Route::CveList, &self.query)
          .unwrap();
        ctx.link().send_message(Msg::Send);
      }
      Msg::Query(query) => {
        match query {
          QueryMsg::Severity(severity) => {
            self.paging.page = 0;
            self.query.severity = Some(severity);
          }
          QueryMsg::Vendor(vendor) => {
            self.paging.page = 0;
            self.query.vendor = Some(vendor);
          }
          QueryMsg::Product(vendor, product) => {
            self.paging.page = 0;
            self.query.vendor = Some(vendor);
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
    let set_vendor = ctx.link().callback(|event: MouseEvent| {
      let target = event.target_unchecked_into::<HtmlButtonElement>();
      Msg::Query(QueryMsg::Vendor(target.get_attribute("value").unwrap()))
    });
    let set_product = ctx.link().callback(|event: MouseEvent| {
      let target = event.target_unchecked_into::<HtmlButtonElement>();
      let vendor = target.get_attribute("vendor").unwrap();
      let product = target.get_attribute("product").unwrap();
      Msg::Query(QueryMsg::Product(vendor, product))
    });
    html! {
      <div class="card">
        {self.query(ctx)}
        <div class="table-responsive">
          <table class="table card-table table-vcenter table-striped table-sm table-hover">
            <CVEHead/>
            <tbody>
            {
              self.result.iter().map(|item| {
              let p = CveProps{props:item.clone(),set_vendor:set_vendor.clone(),set_product:set_product.clone()};
              html!{<>{html!( <CVERow ..p/>) }</>}
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
    let query_severity = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let severity: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      Msg::Query(QueryMsg::Severity(severity))
    });
    let query = ctx
      .link()
      .callback(|args: QueryCve| Msg::Query(QueryMsg::Query(args)));
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
#[function_component]
pub fn CVEHead() -> Html {
  let i18n = use_translation();
  html! {
    <thead>
      <tr>
        <th scope="col">{i18n.t("CVE")}</th>
        <th scope="col">{i18n.t("Vendors")}</th>
        <th scope="col">{i18n.t("Products")}</th>
        <th scope="col">{i18n.t("CWE")}</th>
        <th scope="col">{i18n.t("CVSS")}</th>
        <th scope="col">{i18n.t("Updated")}</th>
      </tr>
    </thead>
  }
}
