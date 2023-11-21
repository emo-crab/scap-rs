use yew::prelude::*;
pub struct Footer;
impl Component for Footer {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
      <footer class="footer footer-transparent mt-auto py-3">
        <div class="container">
          <div class="row text-center align-items-center flex-row-reverse">
            <div class="col-lg-auto ms-lg-auto">

            </div>
            <div class="col-12 col-lg-auto mt-3 mt-lg-0">
              <ul class="list-inline list-inline-dots mb-0">
                <li class="list-inline-item">
                  {"Copyright © 2023"}
                  <a href="https://keybase.io/kaliteam" target="_blank">{"Kali-Team"}</a>{"."}
                  {"All rights reserved."}
                </li>
              </ul>
            </div>
          </div>
        </div>
    </footer>
            }
  }
}
