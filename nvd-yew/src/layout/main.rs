use crate::layout::Footer;
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
      <div class="page-wrapper">
      <div class="page-body">
        <div class="container-xl">
        <Switch<Route> render={Route::switch} />
        </div>
      </div>
      <Footer/>
      </div>
    }
  }
}
