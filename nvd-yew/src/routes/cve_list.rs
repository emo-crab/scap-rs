use crate::component::CVERow;
use crate::console_log;
use crate::modules::cve::{CveInfoList, QueryCve};
use crate::services::cve::cve_list;
use crate::services::FetchState;
use yew::prelude::*;

pub enum Msg {
  SetFetchState(FetchState<CveInfoList>),
  Query,
  GetError,
  NextPage,
}
impl Component for CveInfoList {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    CveInfoList::default()
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
        console_log!("{:?}", self.query);
        self.query.offset = Some(self.query.offset.unwrap_or(0) + self.query.limit.unwrap_or(10));
        ctx.link().send_message(Msg::Query);
      }
    }
    false
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    html! {
      <div class="card">
        <div class="card-body border-bottom py-2">
          <div class="d-flex">
            <div class="text-muted">
              {"Show"}
              <div class="mx-2 d-inline-block">
                <input type="text" class="form-control form-control-sm" value="8" size="3" aria-label="Invoices count"/>
              </div>
              {"entries"}
            </div>
            <div class="ms-auto text-muted">
              {"Search:"}
              <div class="ms-2 d-inline-block">
                <input type="text" class="form-control form-control-sm" aria-label="Search invoice"/>
              </div>
            </div>
          </div>
        </div>
        <div class="table-responsive">
          <table class="table card-table table-vcenter datatable table-striped table-sm">
            <thead>
              <tr>
                <th>{"CVE编号"}</th>
                <th>{"影响供应商"}</th>
                <th>{"影响产品"}</th>
                <th>{"漏洞类型"}</th>
                <th>{"CVSSv2评分"}</th>
                <th>{"CVSSv3评分"}</th>
                <th>{"披露时间"}</th>
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
    html! {
        <div class="card-footer d-flex align-items-center">
          <p class="m-0 text-muted">{"展示"} <span>{offset+1}</span> {"到"} <span>{offset+limit}</span> {"条"} <span>{"总数"}</span>{total} </p>
          <ul class="pagination m-0 ms-auto">
            // {for }
            <li class="page-item disabled">
              <a class="page-link" href="#" tabindex="-1" aria-disabled="true">
                <i class="bi bi-chevron-left"></i>
                {"prev"}
              </a>
            </li>
            <li class="page-item active"><a class="page-link" href="#">{"1"}</a></li>
            <li class="page-item"><a class="page-link" href="#">{"2"}</a></li>
            <li class="page-item"><a class="page-link" href="#">{"3"}</a></li>
            <li class="page-item">
              <button class="page-link" onclick={next_page}>
                {"next"}
                <i class="bi bi-chevron-right"></i>
              </button>
            </li>
          </ul>
        </div>
    }
  }
}
