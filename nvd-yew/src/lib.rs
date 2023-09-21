mod layout;
mod routes;
mod services;
use routes::{switch, Route};
use layout::nav::Nav;
use yew::prelude::*;
use yew_router::prelude::*;
#[function_component(App)]
pub fn app() -> Html {
  // Start of the html! Yew macro
  html! {
  <>
      <BrowserRouter>
          <Nav />
          <Switch<Route> render={switch} />
      </BrowserRouter>
  </>
  }
}
