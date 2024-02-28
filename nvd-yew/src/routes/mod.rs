use std::fmt::{Display, Formatter};
use yew::prelude::*;
use yew_router::prelude::*;

use cpe::VendorProducts;
use cve::CVEDetails;
use cve_list::CveInfoList;
use home::Home;
use kb::KnowledgeBaseInfoList;
use page_not_found::PageNotFound;

mod cve;
mod cve_list;
// mod cvss;
mod cpe;
mod home;
mod kb;
mod page_not_found;

#[derive(Routable, PartialEq, Eq, Clone, Debug)]
pub enum Route {
  #[at("/cve/:id")]
  Cve { id: String },
  #[at("/cve/")]
  CveList,
  #[at("/cpe/")]
  Cpe,
  #[at("/kb/")]
  Kb,
  #[at("/")]
  Home,
  #[not_found]
  #[at("/404")]
  NotFound,
}

impl Display for Route {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    let s = match self {
      Route::Cve { id } => id,
      Route::CveList => "CVE",
      Route::Cpe => "CPE",
      Route::Kb => "KB",
      Route::Home => "Home",
      Route::NotFound => "Not Found",
    };
    f.write_str(s)
  }
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
      Route::Kb => {
        html! { <KnowledgeBaseInfoList /> }
      }
      Route::NotFound => {
        html! { <PageNotFound /> }
      }
    }
  }
}
