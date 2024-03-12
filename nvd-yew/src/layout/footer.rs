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
      <footer class="footer mt-auto py-1">
        <div class="container">
          <div class="row text-center align-items-center flex-row-reverse">
            <div class="col-lg-auto ms-lg-auto">
              <i class="ti ti-alert-triangle text-red"></i>
              {"本站提供的任何内容、代码与服务仅供学习，请勿用于非法用途或盈利，否则后果自负!"}
            </div>
            <div class="col-12 col-lg-auto mt-3 mt-lg-0">
              <ul class="list-inline list-inline-dots mb-0">
                <li class="list-inline-item">
                  <span>{" Copyright © 2023-2024 "}</span>
                  <a href="https://github.com/cn-kali-team" target="_blank">{"三米前有蕉皮 @Kali-Team"}</a>
                  {" All rights reserved. "}
                  <a href="https://github.com/emo-crab/scap-rs/blob/main/LICENSE" target="_blank">{"GPL-3.0-only"}</a>
                </li>
              </ul>
            </div>
          </div>
        </div>
    </footer>
            }
  }
}
