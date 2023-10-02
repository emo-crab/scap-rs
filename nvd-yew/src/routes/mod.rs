mod cve;
mod cve_list;
mod home;
mod page_not_found;
mod cvss;

use cve::CVELDetails;
use cve_list::CVEList;
use home::Home;
use cvss::CVSS;
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
  pub(crate) fn recognize_path(pathname: &str) -> Option<Self> {
    Self::recognize(pathname)
  }
  pub(crate) fn switch(routes: Route) -> Html {
    match routes {
      Route::Home => {
        html! { <Home /> }
      }
      Route::CveList => {
        html! {<CVEList/>}
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
