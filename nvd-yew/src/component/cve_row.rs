use crate::modules::cve::Cve;
use crate::routes::Route;
use cvss::severity::{SeverityTypeV2, SeverityTypeV3};
use std::collections::HashSet;
use yew::prelude::*;
use yew_router::prelude::*;

pub struct CVERow;
impl Component for CVERow {
  type Message = ();
  type Properties = Cve;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let c = ctx.props().clone();
    let cve_id = c.id;
    let description = c
      .description
      .description_data
      .iter()
      .map(|d| d.value.clone())
      .collect::<Vec<String>>();
    let update = c.created_at.to_string();
    let cwe: Vec<String> = c
      .problem_type
      .problem_type_data
      .iter()
      .map(|p| p.description.iter().map(|d| d.value.clone()).collect())
      .collect();
    let vendor_product = c.configurations.unique_vendor_product();
    let vendor: HashSet<String> = HashSet::from_iter(
      vendor_product
        .iter()
        .map(|v| v.vendor.clone())
        .collect::<Vec<String>>(),
    );
    html! {
    <>
        <tr class="table-group-divider">
          <td>
          <Link<Route> classes={classes!("text-reset")} to={Route::Cve{id:{cve_id.clone()}}}>
             <i class="bi bi-arrow-up-left"></i>
              {cve_id.clone()}
          </Link<Route>>
          </td>
          <td>
          {
            vendor.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(index,value)| {
              html!{
              <button  data-bs-toggle="tooltip" data-bs-placement="top" style="--bs-btn-font-weight:0; --bs-btn-padding-y: .1rem; --bs-btn-padding-x: .5rem; --bs-btn-font-size: .65rem;" type="button" class="btn btn-outline-info" key={value.clone()} title={value.clone()}>
              <b class="text-truncate" style="font-size:larger; max-width: 10rem; display: block;">{ value }</b>
              </button>
              }
            }).collect::<Html>()
          }
          {if vendor.len()>3{html!(<i>{format!("{} and more",vendor.len()-2)}</i>)}else{html!()}}
          </td>
          <td>
          {html!(<span class="badge rounded-pill bg-secondary">{vendor_product.len()}</span>)}
          {
            vendor_product.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&2)).map(|(index,value)| {
              html!{
              <button  data-bs-toggle="tooltip" data-bs-placement="top" style="--bs-btn-font-weight:0; --bs-btn-padding-y: .1rem; --bs-btn-padding-x: .5rem; --bs-btn-font-size: .65rem;" type="button" class="btn btn-outline-success" key={value.product.clone()} title={value.product.clone()}>
              <b class="text-truncate" style="font-size:larger; max-width: 10rem; display: block;">{ value.product }</b>
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
            {cvss2(c.cvss2_score)}
          </td>
          <td>
            {cvss3(c.cvss3_score)}
          </td>
          <td>
            {update}
          </td>
        </tr>
        <tr class="table">
          <td colspan="7" class="table text-truncate" style="max-width: 150px;">{description.join("")}</td>
        </tr>
    </>
    }
  }
}
fn cvss2(score: f32) -> Html {
  let severity = cvss::severity::SeverityTypeV2::from(score);
  let severity_class = match severity {
    SeverityTypeV2::None => "bg-secondary",
    SeverityTypeV2::Low => "bg-info",
    SeverityTypeV2::Medium => "bg-warning",
    SeverityTypeV2::High => "bg-danger",
  };
  let score_str = if score == 0.0 {
    String::from("N/A")
  } else {
    score.to_string()
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score_str}</b></span>)
}
fn cvss3(score: f32) -> Html {
  let severity = cvss::severity::SeverityTypeV3::from(score);
  let severity_class = match severity {
    SeverityTypeV3::None => "bg-secondary",
    SeverityTypeV3::Low => "bg-info",
    SeverityTypeV3::Medium => "bg-warning",
    SeverityTypeV3::High => "bg-danger",
    SeverityTypeV3::Critical => "bg-dark",
  };
  let score_str = if score == 0.0 {
    String::from("N/A")
  } else {
    format!("{} {}", score, severity)
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score_str}</b></span>)
}
