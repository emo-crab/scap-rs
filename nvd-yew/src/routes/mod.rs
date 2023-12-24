mod cve;
mod cve_list;
// mod cvss;
mod cpe;
mod home;
mod page_not_found;
mod products;
mod vendor;
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
