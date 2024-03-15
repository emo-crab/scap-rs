use std::str::FromStr;

use yew::prelude::*;

use nvd_model::cwe::Cwe;

use crate::component::MessageContext;
use crate::console_log;
use crate::services::cve::cwe_details;
use crate::services::FetchState;

// 单行的cve信息，和点击供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct WeaknessesProps {
  pub id: String,
}

pub struct CWEDetails {
  cwe: Option<Cwe>,
  i18n: MessageContext,
  _context_listener: ContextHandle<MessageContext>,
}

pub enum Msg {
  SetFetchState(FetchState<Cwe>),
  Send,
  Lang(MessageContext),
}

impl Component for CWEDetails {
  type Message = Msg;
  type Properties = WeaknessesProps;

  fn create(ctx: &Context<Self>) -> Self {
    let (i18n, lang) = ctx
      .link()
      .context::<MessageContext>(ctx.link().callback(Msg::Lang))
      .unwrap();
    Self {
      cwe: None,
      i18n,
      _context_listener: lang,
    }
  }

  fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::Lang(i18n) => {
        self.i18n = i18n;
        return true;
      }
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
      let name = if !cwe.name_zh.is_empty() && self.i18n.current_lang == "zh" {
        cwe.name_zh
      } else {
        cwe.name
      };
      let des = if !cwe.description_zh.is_empty() && self.i18n.current_lang == "zh" {
        cwe.description_zh
      } else {
        cwe.description
      };
      let mut description = des.chars();
      return html! {
          <div class="card">
            <div class="card-header">
              {self.status(&cwe.status)}
              <i class="ti ti-shield-check-filled"></i>
              <h3 class="card-title">{name}<a href={format!("https://cwe.mitre.org/data/definitions/{}.html",cwe.id)} class="text-reset text-nowrap" target="_blank" rel="noreferrer"><i class="ti ti-external-link"></i><span class="card-subtitle">{format!("CWE-{}",cwe.id)}</span></a></h3>
            </div>
          <div class="card-stamp">
              <div class="card-stamp-icon bg-red">
                <i class="ti ti-shield-exclamation"></i>
              </div>
            </div>
            if self.i18n.current_lang=="zh"{
              <div class="card-body">
                  <h3 class="card-title"><span style="fonts-weight:200;text-shadow:none;display:block;float:left;line-height:24px;width:.7em;fonts-size:2.1em;fonts-family:georgia;margin-right:5px;">{description.next().unwrap_or_default()}</span>{description.collect::<String>()}</h3>
                  <p class="text-secondary" style="white-space: pre-line;">{cwe.remediation}</p>
              </div>
            }
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

impl CWEDetails {
  fn status(&self, status: &str) -> Html {
    let i18n_status = self.i18n.t(status);
    match status {
      "Stable" => {
        html! {<div><span class="badge bg-green"><i class="ti ti-check"></i>{i18n_status}</span></div>}
      }
      "Obsolete" => {
        html! {<div><span class="badge bg-azure"><i class="ti ti-urgent"></i>{i18n_status}</span></div>}
      }
      "Incomplete" => {
        html! {<div><span class="badge bg-vk"><i class="ti ti-time-duration-off"></i>{i18n_status}</span></div>}
      }
      "Draft" => {
        html! {<div><span class="badge bg-teal"><i class="ti ti-notes"></i>{i18n_status}</span></div>}
      }
      "Deprecated" => {
        html! {<div><span class="badge bg-red"><i class="ti ti-text-decrease"></i>{i18n_status}</span></div>}
      }
      _ => {
        html! {<div><span class="badge"><i class="ti ti-check"></i>{i18n_status}</span></div>}
      }
    }
  }
}
