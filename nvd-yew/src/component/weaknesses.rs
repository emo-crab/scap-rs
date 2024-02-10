use crate::console_log;
use crate::services::cve::cwe_details;
use crate::services::FetchState;
use nvd_model::cwe::Cwe;
use std::str::FromStr;
use yew::prelude::*;

// 单行的cve信息，和点击供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct WeaknessesProps {
  pub id: String,
}

pub struct CWEDetails {
  cwe: Option<Cwe>,
}

pub enum Msg {
  SetFetchState(FetchState<Cwe>),
  Send,
}

impl Component for CWEDetails {
  type Message = Msg;
  type Properties = WeaknessesProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self { cwe: None }
  }

  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::SetFetchState(state) => {
        match state {
          FetchState::Success(data) => self.cwe = Some(data),
          FetchState::Failed(err) => {
            console_log!("{:?}", err);
          }
        }
        return true;
      }
      Msg::Send => {
        let id = i32::from_str(ctx.props().id.trim_start_matches("CWE-")).unwrap_or(0);
        ctx.link().send_future(async move {
          match cwe_details(id).await {
            Ok(data) => Msg::SetFetchState(FetchState::Success(data)),
            Err(err) => Msg::SetFetchState(FetchState::Failed(err)),
          }
        });
      }
    }
    false
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    if let Some(cwe) = self.cwe.clone() {
      let mut description = cwe.description.chars();
      return html! {
          <div class="card">
            <div class="card-header">
              <i class="ti ti-shield-check-filled"></i>
              <h3 class="card-title">{cwe.name}<span class="card-subtitle">{format!("CWE-{}",cwe.id)}</span></h3>
            </div>
          <div class="card-stamp">
              <div class="card-stamp-icon bg-red">
                <i class="ti ti-shield-exclamation"></i>
              </div>
            </div>
            <div class="card-body">
                <h3 class="card-title"><span style="fonts-weight:200;text-shadow:none;display:block;float:left;line-height:24px;width:.7em;fonts-size:2.1em;fonts-family:georgia;margin-right:5px;">{description.next().unwrap_or_default()}</span>{description.collect::<String>()}</h3>
              </div>
          </div>
      };
    }
    html!()
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Send);
    }
  }
}
