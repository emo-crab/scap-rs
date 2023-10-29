use crate::routes::Route;
use yew::prelude::*;
use yew_router::prelude::*;
pub struct Nav {
  navbar_active: bool,
  expanded: bool,
}
pub enum Msg {
  ToggleNavbar,
}

impl Component for Nav {
  type Message = Msg;
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self {
      navbar_active: true,
      expanded: true,
    }
  }

  fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::ToggleNavbar => {
        self.navbar_active = !self.navbar_active;
        true
      }
    }
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    let Self {  .. } = *self;

    html! {
    <header>
      <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
        <div class="container-fluid">
          <button class="navbar-toggler" type="button" onclick={ctx.link().callback(|_|Msg::ToggleNavbar)} data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav">
            <span class="navbar-toggler-icon"></span>
          </button>
          <Link<Route> classes={classes!("navbar-brand")} to={Route::Home}>
          <img src="https://avatars.githubusercontent.com/u/30642514?v=4" class="img-circle" height="24px" style="margin-bottom: 4px;"/>
          <span>
          {"nvd-rs 演示"}
          </span>
          </Link<Route>>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
              <li class="nav-item">
                <Link<Route> classes={classes!("nav-link")} to={Route::CveList}>{"Vulnerabilities"}</Link<Route>>
              </li>
              // <li class="nav-item">
              //   <Link<Route> classes={classes!("nav-link")} to={Route::CveList}>{"Products"}</Link<Route>>
              // </li>
            </ul>
            <div class="nav-item d-none d-md-flex me-3">
              <div class="btn-list">
                <a href="https://blog.kali-team.cn/donate" class="btn btn-outline-light" target="_blank" rel="noreferrer">
                  <i class="bi bi-suit-heart" style="color: red;"></i>{"Sponsor"}
                </a>
                <a href="https://github.com/emo-cat/nvd-rs" class="btn btn-outline-secondary" target="_blank" rel="noreferrer">
                  <i class="bi-github" style="color: #f8f9fa;">{"Source code"}</i>
                </a>
              </div>
            </div>
          </div>
        </div>
      </nav>
    </header>
        }
  }
}
