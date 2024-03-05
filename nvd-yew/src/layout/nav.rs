use yew::prelude::*;
use yew_router::prelude::*;

use crate::component::LangSelector;
use crate::routes::Route;

pub enum NavMsg {
  Title,
}

pub struct Nav {
  _listener: LocationHandle,
}

pub fn set_title(title: &str) {
  if let Some(window) = web_sys::window() {
    if let Some(doc) = window.document() {
      if let Ok(Some(title_el)) = doc.query_selector("title") {
        title_el.set_text_content(Some(title));
      };
    }
  };
}

impl Component for Nav {
  type Message = NavMsg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let listener = ctx
      .link()
      .add_location_listener(ctx.link().callback(move |_| NavMsg::Title))
      .unwrap();
    Self {
      _listener: listener,
    }
  }
  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      NavMsg::Title => {
        let route = ctx.link().route::<Route>().unwrap(); // handle event
        set_title(&route.to_string());
      }
    }
    true
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
    <header class="navbar navbar-expand-md d-print-none">
      <div class="container-xl">
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbar-menu" aria-controls="navbar-menu" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <h1 class="navbar-brand navbar-brand-autodark d-none-navbar-horizontal pe-0 pe-md-3">
          <Link<Route> classes={classes!("navbar-brand")} to={Route::Home}>
            <img src="https://avatars.githubusercontent.com/u/99640169?v=4" width="110" height="32" class="navbar-brand-image"/>
          </Link<Route>>
        </h1>
        <div class="navbar-nav flex-row order-md-last">
          <div class="nav-item d-none d-md-flex me-3">
            <div class="btn-list">
              <a href="https://blog.kali-team.cn/donate" class="btn btn-light" target="_blank" rel="noreferrer">
                <i class="ti ti-shield-heart text-pink"></i>{"Sponsor"}
              </a>
              <a href="https://github.com/emo-crab/scap-rs" class="btn btn-light" target="_blank" rel="noreferrer">
                <i class="ti ti-brand-github" style="color: light;"></i>{"Source code"}
              </a>
            </div>
          </div>
          <LangSelector/>
        </div>
        <div class="collapse navbar-collapse" id="navbar-menu">
          <div class="d-flex flex-column flex-md-row flex-fill align-items-stretch align-items-md-center">
            <ul class="navbar-nav">
              <li class="nav-item active">
                <Link<Route> classes={classes!("nav-link")} to={Route::CveList}>
                  <span class="nav-link-icon d-md-none d-lg-inline-block ti ti-bug"></span>
                  <span class="nav-link-title">{"CVE"}</span>
                </Link<Route>>
              </li>
              <li class="nav-item">
                <Link<Route> classes={classes!("nav-link")} to={Route::Cpe}>
                  <span class="nav-link-icon d-md-none d-lg-inline-block ti ti-asset"></span>
                  <span class="nav-link-title">{"CPE"}</span>
                </Link<Route>>
              </li>
              <li class="nav-item">
                <Link<Route> classes={classes!("nav-link")} to={Route::Kb}>
                  <span class="nav-link-icon d-md-none d-lg-inline-block ti ti-book"></span>
                  <span class="nav-link-title">{"KB"}</span>
                </Link<Route>>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </header>
    }
  }
}
