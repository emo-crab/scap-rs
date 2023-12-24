use crate::routes::Route;
use yew::prelude::*;
use yew_router::prelude::*;
pub struct PageNotFound;

impl Component for PageNotFound {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
    <div class="empty">
      <div class="empty-img">
      <i class="bi bi-4-square" style="fonts-size: 8rem;"></i>
      <i class="bi bi-0-square" style="fonts-size: 8rem;"></i>
      <i class="bi bi-4-square" style="fonts-size: 8rem;"></i>
      </div>
      <p class="empty-title">{"No page found"}</p>
      <p class="empty-subtitle text-muted">
        {"Try adjusting your search or filter to find what you're looking for."}
      </p>
      <div class="empty-action">
      <Link<Route> classes={classes!("btn","btn-primary")} to={Route::Home}>
         <i class="bi bi-arrow-return-right"></i>
          {"Go back to the homepage"}
      </Link<Route>>
      </div>
    </div>
    }
  }
}
