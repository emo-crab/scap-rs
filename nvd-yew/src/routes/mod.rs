mod cve;
mod cve_list;
// mod cvss;
mod home;
mod page_not_found;
mod vendor;

use crate::modules::cve::CveInfoList;
use cve::CVEDetails;
// use nvd_cvss::Cvss;
use home::Home;
use page_not_found::PageNotFound;
use yew::prelude::*;
use yew_router::prelude::*;
use crate::modules::cpe::VendorInfoList;

#[derive(Routable, PartialEq, Eq, Clone, Debug)]
pub enum Route {
  #[at("/cve/:id")]
  Cve { id: String },
  #[at("/cve/")]
  CveList,
  #[at("/vendor/")]
  Vendor,
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
      Route::Vendor => {
        html! {<VendorInfoList/>}
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
