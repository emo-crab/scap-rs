use yew::prelude::*;

pub struct Nav {
  expanded: bool,
}

impl Component for Nav {
  type Message = ();
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    Self { expanded: true }
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    html! {
      <>
    <div class="mdl-layout mdl-js-layout">
      <header class="mdl-layout__header">
        <div class="mdl-layout__header-row">
          <span class="mdl-layout-title">{"Title"}</span>
          <nav class="mdl-navigation">
            <a class="mdl-navigation__link" href="">{"CVE"}</a>
            <a class="mdl-navigation__link" href="">{"Vendor"}</a>
            <a class="mdl-navigation__link" href="">{"Product"}</a>
            <a class="mdl-navigation__link" href="">{"About"}</a>
          </nav>
          <div class="mdl-layout-spacer"></div>
        </div>
      </header>
      <div class="mdl-layout__drawer">
        <span class="mdl-layout-title">{"Title"}</span>
        <nav class="mdl-navigation">
          <a class="mdl-navigation__link" href="">{"Link"}</a>
          <a class="mdl-navigation__link" href="">{"Link"}</a>
          <a class="mdl-navigation__link" href="">{"Link"}</a>
          <a class="mdl-navigation__link" href="">{"Link"}</a>
        </nav>
      </div>
      <main class="mdl-layout__content">
      </main>
    </div>
      </>
      }
  }
}
