mod component;
mod debug;
mod error;
mod layout;
mod modules;
mod routes;
mod services;

use layout::{Main, Nav};
use yew::prelude::*;
use yew_router::prelude::*;
pub struct App;

/// 因为是单页应用，所以使用HashRouter，这样只要使用actix
impl Component for App {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
    <div class="page">
        <HashRouter>
        <Nav />
        <Main />
        </HashRouter>
    </div>
    }
  }
}
