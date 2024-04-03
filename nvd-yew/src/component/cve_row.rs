use crate::component::cvss_tags::cvss;
use crate::routes::Route;
use std::collections::HashSet;
use std::ops::Deref;

use crate::component::use_translation;
use nvd_model::cve::Cve;
use yew::prelude::*;
use yew_router::prelude::*;

// 单行的cve信息，和点击供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct CveProps {
  pub props: Cve,
  pub set_vendor: Callback<MouseEvent>,
  pub set_product: Callback<MouseEvent>,
}

#[function_component]
pub fn CVERow(props: &CveProps) -> Html {
  let CveProps {
    props,
    set_vendor,
    set_product,
    ..
  } = props;
  let i18n = use_translation();
  let cve_id = props.id.clone();
  let mut description = props
    .description
    .iter()
    .filter(|d| d.lang == i18n.current_lang)
    .map(|d| d.value.clone())
    .collect::<String>();
  // 把第一行丢弃掉，第一行是组件描述
  let lines: Vec<&str> = description.lines().collect();
  if lines.len() >= 2 {
    let desc: Vec<String> = lines
      .iter()
      .enumerate()
      .filter(|(i, _d)| i != &0)
      .map(|(_i, d)| d.to_string())
      .collect();
    description = desc.join("\r\n");
  }
  if description.is_empty() {
    description = props
      .description
      .iter()
      .filter(|d| d.lang == "en")
      .map(|d| d.value.clone())
      .collect::<String>();
  }
  let update = props.updated_at.to_string();
  let cwe: HashSet<String> = props
    .weaknesses
    .iter()
    .map(|p| p.description.iter().map(|d| d.value.clone()).collect())
    .collect();
  let vendor_product = unique_vendor_product(&props.configurations);
  let vendor: HashSet<String> = HashSet::from_iter(
    vendor_product
      .iter()
      .map(|v| v.vendor.clone())
      .collect::<Vec<String>>(),
  );
  let metrics = props.metrics.deref();
  html! {
  <>
      <tr class="table-group-divider">
        <th scope="row"  rowspan="2">
        <Link<Route> classes={classes!(["text-reset", "text-nowrap"])} to={Route::Cve{id:{cve_id.clone()}}}>
           <i class="ti ti-external-link"></i>
            {cve_id.clone()}
        </Link<Route>>
        </th>
        <td class="w-25 text-truncate text-nowrap">
        {
          vendor.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(_index,value)| {
            html!{
            <button onclick={set_vendor.clone()} data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-info" value={value.clone()} key={value.clone()} title={value.clone()}>
            <b value={value.clone()}>{ value }</b>
            </button>
            }
          }).collect::<Html>()
        }
        {if vendor.len()>3{html!(<i>{format!("{} and more",vendor.len()-2)}</i>)}else{html!()}}
        </td>
        <td class="w-25 text-truncate text-nowrap">
        {html!(<span class="badge rounded-pill bg-secondary">{vendor_product.len()}</span>)}
        {
          if !vendor_product.is_empty(){
            vendor_product.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(_index,value)| {
              html!{
              <button onclick={set_product.clone()} data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-success"  value={value.product.clone()} key={value.product.clone()} title={value.product.clone()}>
              <b product={value.product.clone()} vendor={value.vendor.clone()}>{ value.product }</b>
              </button>
              }
            }).collect::<Html>()
          }else{
          html!{
              <button  disabled=true data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-success">
              <b class="text-truncate">{ "N/A" }</b>
              </button>
            }
          }
        }
        {if vendor_product.len()>3{html!(<i>{format!("{} and more",vendor_product.len()-2)}</i>)}else{html!()}}
        </td>
        <td>
          {cwe.iter().map(|w|{
              html!(<span class={classes!(["badge"])}><b style="fonts-size:larger">{w}</b></span>)
          }).collect::<Html>()}
        </td>
        <td>
          {cvss(metrics)}
        </td>
        <td class="text-truncate text-nowrap">
          <span>{update}</span>
        </td>
      </tr>
      <tr class="table-success">
        <th scope="row" colspan="7" class="table table-active text-truncate" style="max-width: 150px;">{description}</th>
      </tr>
  </>
  }
}

pub fn unique_vendor_product(
  nodes: &[nvd_cves::v4::configurations::Node],
) -> HashSet<nvd_cpe::Product> {
  nodes
    .iter()
    .flat_map(|node| node.vendor_product())
    .collect()
}
