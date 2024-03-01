use crate::component::Accordion;
use yew::prelude::*;

pub struct Comments;

impl Component for Comments {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    let default_lang = web_sys::window()
      .unwrap()
      .navigator()
      .language()
      .unwrap_or("en-US".to_string());
    html! {
        <Accordion name={"Comments"}>
        <script src="https://giscus.app/client.js"
            data-repo="emo-crab/scap-rs"
            data-repo-id="R_kgDOJE0AVw"
            data-category="Announcements"
            data-category-id="DIC_kwDOJE0AV84CcTem"
            data-mapping="title"
            data-strict="1"
            data-reactions-enabled="1"
            data-emit-metadata="0"
            data-input-position="top"
            data-theme="preferred_color_scheme"
            data-lang={default_lang}
            data-loading="lazy"
            crossorigin="anonymous">
        </script>
        </Accordion>
    }
  }
}
