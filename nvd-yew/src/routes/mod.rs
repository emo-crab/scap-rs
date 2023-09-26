mod home;
mod page_not_found;

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
      Route::NotFound => {
        html! { <PageNotFound /> }
      }
      _ => {
        html! { <PageNotFound /> }
      }
    }
  }
}
