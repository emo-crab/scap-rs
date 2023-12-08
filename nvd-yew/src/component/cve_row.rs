use crate::component::cvss_tags::{cvss2, cvss3};
use crate::modules::cve::Cve;
use crate::routes::Route;
use std::collections::HashSet;

use yew::prelude::*;
use yew_router::prelude::*;

// 单行的cve信息，和点击供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct CveProps {
    pub props: Cve,
    pub set_vendor: Callback<MouseEvent>,
    pub set_product: Callback<MouseEvent>,
}

pub struct CVERow;

impl Component for CVERow {
    type Message = ();
    type Properties = CveProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let CveProps {
            props,
            set_vendor,
            set_product,
            ..
        } = ctx.props().clone();
        let cve_id = props.id;
        let description = props
            .description
            .iter()
            .map(|d| d.value.clone())
            .collect::<Vec<String>>();
        let update = props.created_at.to_string();
        let cwe: Vec<String> = props
            .weaknesses
            .iter()
            .map(|p| p.description.iter().map(|d| d.value.clone()).collect())
            .collect();
        let vendor_product = unique_vendor_product(props.configurations);
        let vendor: HashSet<String> = HashSet::from_iter(
            vendor_product
                .iter()
                .map(|v| v.vendor.clone())
                .collect::<Vec<String>>(),
        );
        let metrics = props.metrics.clone();
        let v3 = if metrics.base_metric_v31.inner().is_some() {
            metrics.base_metric_v31.inner()
        } else {
            metrics.base_metric_v3.inner()
        };
        html! {
    <>
        <tr class="table-group-divider">
          <th scope="row">
          <Link<Route> classes={classes!("text-reset")} to={Route::Cve{id:{cve_id.clone()}}}>
             <i class="ti ti-external-link"></i>
              {cve_id.clone()}
          </Link<Route>>
          </th>
          <td>
          {
            vendor.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(_index,value)| {
              html!{
              <button onclick={set_vendor.clone()} data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-info" value={value.clone()} key={value.clone()} title={value.clone()}>
              <b class="text-truncate" value={value.clone()}>{ value }</b>
              </button>
              }
            }).collect::<Html>()
          }
          {if vendor.len()>3{html!(<i>{format!("{} and more",vendor.len()-2)}</i>)}else{html!()}}
          </td>
          <td>
          {html!(<span class="badge rounded-pill bg-secondary">{vendor_product.len()}</span>)}
          {
            vendor_product.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(_index,value)| {
              html!{
              <button onclick={set_product.clone()} data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-success"  value={value.product.clone()} key={value.product.clone()} title={value.product.clone()}>
              <b class="text-truncate" product={value.product.clone()} vendor={value.vendor.clone()}>{ value.product }</b>
              </button>
              }
            }).collect::<Html>()
          }
          {if vendor_product.len()>3{html!(<i>{format!("{} and more",vendor_product.len()-2)}</i>)}else{html!()}}
          </td>
          <td>
            {cwe}
          </td>
          <td>
            {cvss2(metrics.base_metric_v2.inner())}
          </td>
          <td>
            {cvss3(v3)}
          </td>
          <td>
            {update}
          </td>
        </tr>
        <tr class="table table-success">
          <th scope="row" colspan="7" class="table text-truncate" style="max-width: 150px;">{description.join("")}</th>
        </tr>
    </>
    }
    }
}

pub fn unique_vendor_product(nodes: Vec<nvd_cves::v4::configurations::Node>) -> Vec<nvd_cpe::Product> {
    nodes
        .iter()
        .flat_map(|node| node.vendor_product())
        .collect()
}
