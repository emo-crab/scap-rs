use crate::component::use_translation;
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

#[function_component]
pub fn CVEQuery(props: &CVEQueryProps) -> Html {
  let i18n = use_translation();
  let query = props.props.clone();
  let query_severity = props.query_severity.clone();
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
    let query_callback = props.query.clone();
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
        page: None,
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
        <div class="col">
        <div class="dropdown">
          <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown">
          <i class="ti ti-select"></i>{i18n.t("Severity")}
          </button>
          <div class="dropdown-menu">
            <li><button onclick={query_severity.clone()} type="button" value="none"><span class="dropdown-item btn bg-secondary btn-sm" style="pointer-events: none;"></span>{i18n.t("none")+" (0.0)"}</button></li>
            <li><button onclick={query_severity.clone()} type="button" value="low"><span class="dropdown-item btn bg-info btn-sm" style="pointer-events: none;"></span>{i18n.t("low")+" (0.1-3.9)"}</button></li>
            <li><button onclick={query_severity.clone()} type="button" value="medium"><span class="dropdown-item btn bg-warning btn-sm" style="pointer-events: none;"></span>{i18n.t("medium")+" (4.0-6.9)"}</button></li>
            <li><button onclick={query_severity.clone()} type="button" value="high"><span  class="dropdown-item btn bg-danger btn-sm" style="pointer-events: none;"></span>{i18n.t("high")+" (7.0-8.9)"}</button></li>
            <li><button onclick={query_severity.clone()} type="button" value="critical"><span class="dropdown-item btn text-light bg-dark btn-sm" style="pointer-events: none;"></span>{i18n.t("critical")+" (9.0-10.0)"}</button></li>
          </div>
          <input class="form-control" style="display: none;" readonly=true ref={severity_input} value={query.severity.clone()}/>
        </div>
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
