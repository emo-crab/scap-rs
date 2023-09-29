use yew::prelude::*;

pub struct CVEPagination;
impl Component for CVEPagination {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
        <div class="card-footer d-flex align-items-center">
          <p class="m-0 text-muted">{"展示"} <span>{"1"}</span> {"到"} <span>{"10"}</span> {"条"} <span>{"总数"}</span>{"16"} </p>
          <ul class="pagination m-0 ms-auto">
            <li class="page-item disabled">
              <a class="page-link" href="#" tabindex="-1" aria-disabled="true">
                <i class="bi bi-chevron-left"></i>
                {"prev"}
              </a>
            </li>
            <li class="page-item active"><a class="page-link" href="#">{"1"}</a></li>
            <li class="page-item"><a class="page-link" href="#">{"2"}</a></li>
            <li class="page-item"><a class="page-link" href="#">{"3"}</a></li>
            <li class="page-item">
              <a class="page-link" href="#">
                {"next"}
                <i class="bi bi-chevron-right"></i>
              </a>
            </li>
          </ul>
        </div>
    }
  }
}
