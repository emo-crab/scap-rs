use crate::component::CVSS3;
use yew::prelude::*;
pub struct Cvss;
impl Component for Cvss {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
            <>
    <div class="card">
      <ul class="nav nav-tabs" data-bs-toggle="tabs">
        <li class="nav-item">
          <a href="#tabs-cvss3" class="nav-link active" data-bs-toggle="tab">{"CVSS v3"}</a>
        </li>
        <li class="nav-item">
          <a href="#tabs-cvss2" class="nav-link" data-bs-toggle="tab">{"CVSS v2"}</a>
        </li>
      </ul>
      <div class="card-body">
        <div class="tab-content">
          <div class="tab-pane show active" id="tabs-cvss3">
            <CVSS3 v3={None}/>
          </div>
          <div class="tab-pane" id="tabs-cvss2">
            <div>{"Fringilla egestas nunc quis tellus diam rhoncus ultricies tristique enim at diam, sem nunc amet, pellentesque id egestas velit sed"}</div>
          </div>
        </div>
      </div>
    </div>
    </>
    }
  }
}
