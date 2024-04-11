use crate::component::use_translation;
use nvd_model::product::QueryProduct;
use web_sys::{HtmlButtonElement, HtmlInputElement};
use yew::prelude::*;

// CVE表过滤和查询回调函数
#[derive(PartialEq, Clone, Properties)]
pub struct CPEQueryProps {
  pub props: QueryProduct,
  #[prop_or_default]
  pub is_product: Option<bool>,
  pub query_part: Callback<MouseEvent>,
  pub query: Callback<QueryProduct>,
}

#[function_component]
pub fn CPEQuery(props: &CPEQueryProps) -> Html {
  let i18n = use_translation();
  let is_product = props.is_product.unwrap_or_default();
  let query = props.props.clone();
  let query_part = props.query_part.clone();
  let part_input = NodeRef::default();
  let vendor_input = NodeRef::default();
  let product_input = NodeRef::default();
  let search_input = NodeRef::default();
  let submit_button = NodeRef::default();
  // 点击的是b标签，但是事件冒泡会将事件传到按钮
  let on_submit = {
    let part_input = part_input.clone();
    let vendor_input = vendor_input.clone();
    let product_input = product_input.clone();
    let query = query.clone();
    let query_callback = props.query.clone();
    Callback::from(move |event: SubmitEvent| {
      event.prevent_default();
      let part = if is_product {
        part_input.cast::<HtmlInputElement>().unwrap().value()
      } else {
        String::new()
      };
      let vendor = vendor_input
        .cast::<HtmlInputElement>()
        .unwrap()
        .value()
        .trim()
        .to_string();
      let product = if is_product {
        product_input
          .cast::<HtmlInputElement>()
          .unwrap()
          .value()
          .trim()
          .to_string()
      } else {
        String::new()
      };
      // let search = search_input.cast::<HtmlInputElement>().unwrap().value();
      query_callback.emit(QueryProduct {
        vendor_id: None,
        vendor_name: if vendor.is_empty() {
          None
        } else {
          Some(vendor)
        },
        name: if product.is_empty() {
          None
        } else {
          Some(product)
        },
        part: if part.is_empty() { None } else { Some(part) },
        size: query.size,
        page: None,
        official: None,
      })
    })
  };
  let clean = {
    let part_input = part_input.clone();
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
        "part_input" => {
          part_input.cast::<HtmlInputElement>().unwrap().set_value("");
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
        <div class="col input-icon input-group input-group-flat text-muted">
          <input type="text" class="form-control"  aria-label="vendor" placeholder="Vendor" ref={vendor_input} value={query.vendor_name.clone()}/>
          <button class="input-group-text" onclick={clean.clone()} value="vendor_input"><i class="ti ti-x link-danger"></i></button>
        </div>
        if is_product{
        <div class="col input-icon input-group input-group-flat text-muted">
          <input type="text" class="form-control" aria-label="product" placeholder="Product" ref={product_input} value={query.name.clone()}/>
          <button class="input-group-text" onclick={clean.clone()} value="product_input"><i class="ti ti-x link-danger"></i></button>
        </div>
        <div class="col">
          <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
            <i class="ti ti-separator"></i>{i18n.t("Part")}
          </button>
          <div class="dropdown-menu">
            <li><button onclick={query_part.clone()} type="button" value="none"><span class="dropdown-item btn bg-secondary btn-sm" style="pointer-events: none;"></span>{i18n.t("none")}</button></li>
            <li><button onclick={query_part.clone()} type="button" value="a"><span class="dropdown-item btn bg-info btn-sm" style="pointer-events: none;"></span>{i18n.t("application")}</button></li>
            <li><button onclick={query_part.clone()} type="button" value="o"><span class="dropdown-item btn bg-warning btn-sm" style="pointer-events: none;"></span>{i18n.t("operating system")}</button></li>
            <li><button onclick={query_part.clone()} type="button" value="h"><span class="dropdown-item btn bg-danger btn-sm" style="pointer-events: none;"></span>{i18n.t("hardware devices")}</button></li>
          </div>
        <input type="text" class="form-control" style="display: none;" readonly=true ref={part_input} value={query.part.clone()}/>
        </div>
        }
      <div class="col-auto d-flex">
      <button class="btn" type="submit" ref={submit_button}><i class="ti ti-search"></i></button>
      </div>
      </form>
    </div>
  </div>
      }
}
