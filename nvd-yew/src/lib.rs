mod layout;
mod routes;
mod services;
use routes::Route;
use layout::nav::Nav;
use yew::prelude::*;
use yew_router::prelude::*;
#[function_component(App)]
pub fn app() -> Html {
  html! {
  <>
      <BrowserRouter>
          <Nav />
          <Switch<Route> render={Route::switch} />
      </BrowserRouter>
  </>
  }
}
