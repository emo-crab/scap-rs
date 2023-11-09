use crate::console_log;
use crate::modules::cve::Cve;
use crate::services::cve::cve_details;
use crate::services::FetchState;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct CVEProps {
  pub id: String,
}
pub enum Msg {
  SetFetchState(FetchState<Cve>),
  Send,
}
pub struct CVELDetails {
  cve: Option<Cve>,
}
impl Component for CVELDetails {
  type Message = Msg;
  type Properties = CVEProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self { cve: None }
  }
  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::SetFetchState(state) => {
        match state {
          FetchState::Success(data) => self.cve = Some(data),
          FetchState::Failed(err) => {
            console_log!("{:?}", err);
          }
        }
        return true;
      }
      Msg::Send => {
        let id = ctx.props().id.clone();
        ctx.link().send_future(async {
          match cve_details(id).await {
            Ok(data) => Msg::SetFetchState(FetchState::Success(data)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
    }
    false
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    if let None = self.cve {
      return html!();
    }
    let cve = self.cve.clone().unwrap();
    console_log!("{:?}", cve);
    html! {
      <div class="card">
        <h5 class="card-header">{cve.id}</h5>
      </div>
    }
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Send);
    }
  }
}
