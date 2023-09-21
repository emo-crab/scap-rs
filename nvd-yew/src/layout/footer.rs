use yew::prelude::*;

#[function_component(Footer)]
pub fn view() -> Html {
  html! {
          <footer class="footer">
              <div class="content has-text-centered">
                  { "Powered by " }
                  <a href="https://yew.rs">{ "Yew" }</a>
                  { " using " }
                  <a href="https://bulma.io">{ "Bulma" }</a>
                  { " and images from " }
                  <a href="https://unsplash.com">{ "Unsplash" }</a>
              </div>
          </footer>
  }
}
