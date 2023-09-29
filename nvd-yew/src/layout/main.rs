use crate::routes::Route;
use yew::prelude::*;
use yew_router::prelude::*;
pub struct Main;
impl Component for Main {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
      <main role="main">
        <div class="container" style="padding: 60px 15px 0;">
        <Switch<Route> render={Route::switch} />
      </div>
      </main>
    }
  }
}
