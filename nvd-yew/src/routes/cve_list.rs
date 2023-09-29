use crate::component::{CVEPagination, CVERow};
use yew::prelude::*;
pub struct CVEList;
impl Component for CVEList {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    let items = (1..=10).collect::<Vec<_>>();
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
            { items.into_iter().map(|_name| {
              html!{<>{html!( <CVERow/>) }</>}
                }).collect::<Html>()
              }
            </tbody>
          </table>
        </div>
      <CVEPagination />
      </div>
    }
  }
}
