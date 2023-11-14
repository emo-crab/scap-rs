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
impl Component for App {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
    <div class="page">
        <BrowserRouter>
        <Nav />
        <Main />
        </BrowserRouter>
    </div>
    }
  }
}
