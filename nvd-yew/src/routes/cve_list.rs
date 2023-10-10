use crate::component::{CVEPagination, CVERow};
use crate::console_log;
use crate::modules::cve::CveInfoList;
use crate::services::cve::cve_list;
use crate::services::FetchState;
use yew::prelude::*;

pub enum Msg {
  SetFetchState(FetchState<CveInfoList>),
  Get,
  GetError,
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
        return true;
      }
      Msg::Get => {
        ctx.link().send_future(async {
          match cve_list().await {
            Ok(md) => Msg::SetFetchState(FetchState::Success(md)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
      Msg::GetError => {}
      _ => {}
    }
    false
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    html! {
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">{"Vulnerabilities (CVE)"}</h3>
        </div>
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
          <table class="table card-table table-vcenter text-nowrap datatable">
            <thead>
              <tr>
                <th class="w-1">{"CVE编号"}</th>
                <th>{"漏洞名称"}</th>
                <th>{"漏洞类型"}</th>
                <th>{"CVSS评分"}</th>
                <th>{"披露时间"}</th>
                <th>{"Status"}</th>
                <th>{"Price"}</th>
                <th></th>
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
      <CVEPagination />
      </div>
    }
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Get);
    }
  }
}
