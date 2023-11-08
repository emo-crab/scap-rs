use crate::console_log;
use crate::modules::cve::QueryCve;
use web_sys::HtmlInputElement;
use yew::prelude::*;

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
    let on_submit = {
      let severity_input = severity_input.clone();
      let vendor_input = vendor_input.clone();
      let product_input = product_input.clone();
      let search_input = search_input.clone();
      let query = query.clone();
      let query_callback = ctx.props().query.clone();
      Callback::from(move |event: SubmitEvent| {
        event.prevent_default();
        let target = event.target().unwrap();
        let severity = severity_input.cast::<HtmlInputElement>().unwrap().value();
        let vendor = vendor_input.cast::<HtmlInputElement>().unwrap().value();
        let product = product_input.cast::<HtmlInputElement>().unwrap().value();
        let search = search_input.cast::<HtmlInputElement>().unwrap().value();
        query_callback.emit(QueryCve {
          id: if search.is_empty() {
            None
          } else {
            Some(search)
          },
          year: None,
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
          limit: query.limit,
          offset: query.offset,
        })
      })
    };
    html! {
    <div class="card-body border-bottom py-1">

        <form class="row g-1" onsubmit={on_submit}>
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
          <input class="form-control form-control-sm" style="height: min-content;" readonly=true ref={severity_input} value={query.severity.clone()}/>
          </div>
          <div class="col input-group input-group-sm text-muted" style="height: min-content;">
            <span class="input-group-text bg-info">{"Vendor"}</span>
            <input type="text" class="form-control"  aria-label="vendor" ref={vendor_input} value={query.vendor.clone()}/>
          </div>
          <div class="col input-group input-group-sm text-muted" style="height: min-content;">
            <span class="input-group-text bg-success">{"Product"}</span>
            <input type="text" class="form-control" aria-label="product" ref={product_input} value={query.product.clone()}/>
          </div>
          <div class="col d-flex">
          <div class="input-group input-group-sm text-muted" style="height: min-content;">
            <span class="input-group-text">{"Search"}</span>
            <input type="text" class="form-control form-control-sm" aria-label="Search invoice" ref={search_input} value={query.id.clone()}/>
            <button class="btn btn-secondary" type="submit"><i class="bi bi-search"></i></button>
          </div>
          </div>
        </form>
    </div>
        }
  }
}
