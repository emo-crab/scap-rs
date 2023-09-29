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
    <footer class="footer footer-transparent mt-auto py-3 bg-light">
              <div class="container">
                <div class="row text-center align-items-center flex-row-reverse">
                  <div class="col-lg-auto ms-lg-auto">
                    <ul class="list-inline list-inline-dots mb-0">
                      <li class="list-inline-item"><a href="./docs/index.html" class="link-secondary">{"Documentation"}</a></li>
                      <li class="list-inline-item"><a href="./license.html" class="link-secondary">{"License"}</a></li>
                      <li class="list-inline-item"><a href="https://github.com/tabler/tabler" target="_blank" class="link-secondary" rel="noopener">{"Source code"}</a></li>
                      <li class="list-inline-item">
                        <a href="https://github.com/sponsors/codecalm" target="_blank" class="link-secondary" rel="noopener">
                          {"Sponsor"}
                        </a>
                      </li>
                    </ul>
                  </div>
                  <div class="col-12 col-lg-auto mt-3 mt-lg-0">
                    <ul class="list-inline list-inline-dots mb-0">
                      <li class="list-inline-item">
                        {"Copyright © 2023"}
                        <a href="." class="link-secondary">{"Kali-Team"}</a>{"."}
                        {"All rights reserved."}
                      </li>
                      <li class="list-inline-item">
                        <a href="./changelog.html" class="link-secondary" rel="noopener">{"v1.0.0-beta3"}</a>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </footer>
          }
  }
}
