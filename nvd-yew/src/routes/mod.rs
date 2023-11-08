mod cve;
mod cve_list;
mod cvss;
mod home;
mod page_not_found;

use crate::modules::cve::CveInfoList;
use cve::CVELDetails;
use cvss::CVSS;
use home::Home;
use page_not_found::PageNotFound;
use yew::prelude::*;
use yew_router::prelude::*;
#[derive(Routable, PartialEq, Eq, Clone, Debug)]
pub enum Route {
  #[at("/cve/:id")]
  Cve { id: String },
  #[at("/cve")]
  CveList,
  #[at("/")]
  Home,
  #[at("/cvss")]
  CVSS,
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
        html! {<CVELDetails id={id}/ >}
      }
      Route::CVSS => {
        html! { <CVSS /> }
      }
      Route::NotFound => {
        html! { <PageNotFound /> }
      }
      _ => {
        html! { <PageNotFound /> }
      }
    }
  }
}
