use yew::prelude::*;

pub struct Home;
impl Component for Home {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
        <>
      <div class="album py-4" id="itl-header">
          <div class="container vuln-list-container">
              <div class="header__content">
                  <div class="header__text">
                      <h1 class="header__title ">{"高危漏洞库"}</h1>
                      <div class="header__lede">{"阿里云安全专家专业评估分析，帮助客户精准研判高危风险漏洞。"}</div>
                  </div>
              </div>
          </div>
      </div>
    <section id="feature_slider">
        <article class="slide" id="showcasing" style="background: url('/static/welcome/img/indigo.jpg') repeat-x top center;">
            <img class="asset" src="/static/welcome/img/cve_details.png"/>
            <div class="info">
                <h2>{"Move Security Forward"}</h2>
                <p>{"OpenCVE is the easiest way to track CVE updates and be alerted about new vulnerabilities."}</p>
                <a class="btn-header" href="/register">{"Sign Up For Free"}</a>
            </div>
        </article>
    </section>
        </>
        }
  }
}
