mod cve;
mod cve_list;
// mod cvss;
mod cpe;
mod home;
mod page_not_found;

use cve::CVEDetails;
use cve_list::CveInfoList;
// use nvd_cvss::Cvss;
use cpe::VendorProducts;
use home::Home;
use page_not_found::PageNotFound;
use yew::prelude::*;
use yew_router::prelude::*;

#[derive(Routable, PartialEq, Eq, Clone, Debug)]
pub enum Route {
  #[at("/cve/:id")]
  Cve { id: String },
  #[at("/cve/")]
  CveList,
  #[at("/cpe/")]
  Cpe,
  #[at("/")]
  Home,
  #[not_found]
  #[at("/404")]
  NotFound,
}

impl Route {
  pub(crate) fn switch(routes: Route) -> Html {
    match routes {
      Route::Home => {
        html! { <Home /> }
      }
      Route::CveList => {
        html! {<CveInfoList/>}
      }
      Route::Cve { id } => {
        html! {<CVEDetails id={id}/ >}
      }
      Route::Cpe => {
        html! {<VendorProducts/>}
      }
      // Route::Cvss => {
      //   html! { <Cvss /> }
      // }
      Route::NotFound => {
        html! { <PageNotFound /> }
      }
    }
  }
}

pub fn set_title(title: &str) {
  if let Some(window) = web_sys::window() {
    if let Some(doc) = window.document() {
      if let Ok(Some(title_el)) = doc.query_selector("title") {
        title_el.set_inner_html(title);
      };
    }
  };
}
pub fn set_token_to_local_storage() {
  if let Some(window) = web_sys::window() {
    if let Ok(location) = web_sys::Url::new(
      &window
        .location()
        .to_string()
        .as_string()
        .unwrap_or_default(),
    ) {
      if let Some(session) = location.search_params().get("giscus") {
        if let Ok(Some(s)) = window.local_storage() {
          s.set_item("giscus-session", &format!("\"{}\"", session))
            .unwrap_or_default();
        }
      }
    }
  };
}
