mod layout;
mod routes;
mod services;
mod component;
mod error;
mod modules;
mod debug;

use layout::{Footer, Main, Nav};
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
    <>
        <BrowserRouter>
        <Nav />
        <Main />
        <Footer/>
        </BrowserRouter>
    </>
    }
  }
}
