use std::collections::HashMap;
use yew::prelude::*;
use yew_router::prelude::*;

use layout::{Main, Nav};
use crate::component::I18nProvider;

mod component;
mod debug;
mod error;
mod layout;
mod modules;
mod routes;
mod services;

pub struct App;

/// 因为是单页应用，所以使用HashRouter，这样只要使用actix
impl Component for App {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    let mut translations: HashMap<String, HashMap<String, String>> = HashMap::new();
    translations.insert("zh".to_string(), HashMap::from_iter([("Home".to_string(), "主页".to_string())]));
    translations.insert("en".to_string(), HashMap::from_iter([("Home".to_string(), "Home".to_string())]));
    html! {
    <div class="page">
        <BrowserRouter>
        <I18nProvider translations={translations}>
        <Nav />
        <Main />
        </I18nProvider>
        </BrowserRouter>
    </div>
    }
  }
}
