use crate::routes::Route;
use web_sys::console;
use yew::prelude::*;
use yew_router::prelude::*;
pub struct Nav {
  navbar_active: bool,
  expanded: bool,
}
pub enum Msg {
  ToggleNavbar,
}

impl Nav {
  fn is_active(ctx: &Context<Self>) -> String {
    let route: Route = ctx.link().route().unwrap();
    console::log_1(&wasm_bindgen::JsValue::from(route.to_path()));
    return if matches!(route, Route::CveList) {
      "active".to_string()
    } else {
      String::new()
    };
  }
}
impl Component for Nav {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    Self {
      navbar_active: true,
      expanded: true,
    }
  }

  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::ToggleNavbar => {
        self.navbar_active = !self.navbar_active;
        true
      }
    }
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    let Self { navbar_active, .. } = *self;

    html! {
    <header>
      <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
        <div class="container-fluid">
          <button class="navbar-toggler" type="button" onclick={ctx.link().callback(|_|Msg::ToggleNavbar)} data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav">
            <span class="navbar-toggler-icon"></span>
          </button>
          <Link<Route> classes={classes!("navbar-brand")} to={Route::Home}>
          <img src="https://avatars.githubusercontent.com/u/30642514?v=4" class="img-circle" height="30px" style="margin-bottom: 4px;"/>
          <span style="font-size: 24px; font-weight: 500; padding-left: 5px;">
          {"nvd-rs 演示"}
          </span>
          </Link<Route>>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
              <li class="nav-item">
                <Link<Route> classes={classes!("nav-link",Nav::is_active(ctx))} to={Route::CveList}>{"Vulnerabilities"}</Link<Route>>
              </li>
              <li class="nav-item">
                <Link<Route> classes={classes!("nav-link")} to={Route::CveList}>{"Products"}</Link<Route>>
              </li>
            </ul>
            <div class="nav-item d-none d-md-flex me-3">
              <div class="btn-list">
                <a href="https://github.com/emo-cat/nvd-rs" class="btn btn-outline-secondary" target="_blank" rel="noreferrer">
                  <i class="bi-github" style="color: #f8f9fa;">{"Source code"}</i>
                </a>
                <a href="https://github.com/sponsors/codecalm" class="btn btn-outline-light" target="_blank" rel="noreferrer">
                  <i class="bi bi-suit-heart" style="color: red;"></i>{"Sponsor"}
                </a>
              </div>
            </div>
            <form class="d-flex">
              <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search"/>
              <button class="btn btn-outline-light" type="submit">{"Search"}</button>
            </form>
          </div>
        </div>
      </nav>
    </header>
        }
  }
}
