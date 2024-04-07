use nvd_model::cve::QueryCve;
use web_sys::{HtmlButtonElement, HtmlInputElement};
use yew::prelude::*;

// CVE表过滤和查询回调函数
#[derive(PartialEq, Clone, Properties)]
pub struct CVEQueryProps {
  pub props: QueryCve,
  pub query_severity: Callback<MouseEvent>,
  pub query: Callback<QueryCve>,
}
pub struct CVEQuery;
impl Component for CVEQuery {
  type Message = ();
  type Properties = CVEQueryProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let query = ctx.props().props.clone();
    let query_severity = ctx.props().query_severity.clone();
    let severity_input = NodeRef::default();
    let vendor_input = NodeRef::default();
    let product_input = NodeRef::default();
    let search_input = NodeRef::default();
    let submit_button = NodeRef::default();
    // 点击的是b标签，但是事件冒泡会将事件传到按钮
    let on_submit = {
      let severity_input = severity_input.clone();
      let vendor_input = vendor_input.clone();
      let product_input = product_input.clone();
      let search_input = search_input.clone();
      let query = query.clone();
      let query_callback = ctx.props().query.clone();
      Callback::from(move |event: SubmitEvent| {
        event.prevent_default();
        let severity = severity_input
          .cast::<HtmlInputElement>()
          .unwrap()
          .value()
          .trim()
          .to_string();
        let vendor = vendor_input
          .cast::<HtmlInputElement>()
          .unwrap()
          .value()
          .trim()
          .to_string();
        let product = product_input
          .cast::<HtmlInputElement>()
          .unwrap()
          .value()
          .trim()
          .to_string();
        let search = search_input
          .cast::<HtmlInputElement>()
          .unwrap()
          .value()
          .trim()
          .to_string();
        query_callback.emit(QueryCve {
          id: if search.is_empty() {
            None
          } else {
            Some(search)
          },
          year: None,
          official: None,
          translated: None,
          vendor: if vendor.is_empty() {
            None
          } else {
            Some(vendor)
          },
          product: if product.is_empty() {
            None
          } else {
            Some(product)
          },
          severity: if severity.is_empty() {
            None
          } else {
            Some(severity)
          },
          size: query.size,
          page: query.page,
          order: None,
        })
      })
    };
    let clean = {
      let severity_input = severity_input.clone();
      let vendor_input = vendor_input.clone();
      let product_input = product_input.clone();
      let search_input = search_input.clone();
      let submit_button = submit_button.clone();
      Callback::from(move |event: MouseEvent| {
        let target = event
          .target_unchecked_into::<HtmlButtonElement>()
          .parent_element()
          .unwrap();
        let v = target.get_attribute("value").unwrap_or_default();
        match v.as_str() {
          "severity_input" => {
            severity_input
              .cast::<HtmlInputElement>()
              .unwrap()
              .set_value("");
          }
          "vendor_input" => {
            vendor_input
              .cast::<HtmlInputElement>()
              .unwrap()
              .set_value("");
          }
          "product_input" => {
            product_input
              .cast::<HtmlInputElement>()
              .unwrap()
              .set_value("");
          }
          "search_input" => {
            search_input
              .cast::<HtmlInputElement>()
              .unwrap()
              .set_value("");
          }
          _ => {}
        }
        submit_button.cast::<HtmlButtonElement>().unwrap().click();
      })
    };
    html! {
    <div class="card-body border-bottom py-1">
      <div class="d-flex">
        <form class="row g-1 d-flex" onsubmit={on_submit}>
          <div class="col input-group input-group-flat">
          <div class="dropdown">
            <button class="btn dropdown-toggle" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {"Severity"}
            </button>
            <ul class="dropdown-menu">
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-secondary btn-sm"  value="none">{"none (0.0)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-info btn-sm" value="low">{"low (0.1-3.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-warning btn-sm" value="medium">{"medium (4.0-6.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn bg-danger btn-sm" value="high">{"high (7.0-8.9)"}</button></li>
              <li><button onclick={query_severity.clone()} type="button" class="dropdown-item btn text-light bg-dark btn-sm" value="critical">{"critical (9.0-10.0)"}</button></li>
            </ul>
          </div>
          <input class="form-control" readonly=true ref={severity_input} value={query.severity.clone()}/>
          <button class="input-group-text" onclick={clean.clone()} value="severity_input"><i class="ti ti-x link-danger"></i></button>
          </div>
          <div class="col input-icon input-group input-group-flat text-muted">
            <input type="text" class="form-control"  aria-label="vendor" placeholder="Vendor" ref={vendor_input} value={query.vendor.clone()}/>
            <button class="input-group-text" onclick={clean.clone()} value="vendor_input"><i class="ti ti-x link-danger"></i></button>
          </div>
          <div class="col input-icon input-group input-group-flat text-muted">
            <input type="text" class="form-control" aria-label="product" placeholder="Product" ref={product_input} value={query.product.clone()}/>
            <button class="input-group-text" onclick={clean.clone()} value="product_input"><i class="ti ti-x link-danger"></i></button>
          </div>
          <div class="col input-icon input-group input-group-flat text-muted">
            <input type="text" value="" class="form-control" placeholder="Search" ref={search_input} value={query.id.clone()}/>
            <button class="input-group-text bg-outline-danger" onclick={clean.clone()} value="search_input"><i class="ti ti-x link-danger"></i></button>
            <button class="btn" type="submit" ref={submit_button}><i class="ti ti-search"></i></button>
          </div>
        </form>
      </div>
    </div>
        }
  }
}
