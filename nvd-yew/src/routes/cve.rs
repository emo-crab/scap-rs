use crate::component::CVSS3;
use crate::console_log;
use crate::modules::cve::Cve;
use crate::routes::Route;
use crate::services::cve::cve_details;
use crate::services::FetchState;
use cvss::v3::ImpactMetricV3;
use std::str::FromStr;
use yew::prelude::*;
use yew_router::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct CVEProps {
  pub id: String,
}
pub enum Msg {
  SetFetchState(FetchState<Cve>),
  Send,
}
pub struct CVEDetails {
  cve: Option<Cve>,
}
impl Component for CVEDetails {
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
      return html! {
        <div class="container container-slim py-4">
        <div class="text-center">
          <div class="mb-3">
            <a class="navbar-brand navbar-brand-autodark"></a>
          </div>
          <div class="text-secondary mb-3">{"Loading"}</div>
          <div class="progress progress-sm">
            <div class="progress-bar progress-bar-indeterminate"></div>
          </div>
        </div>
      </div>
      };
    }
    let cve = self.cve.clone().unwrap();
    let description = cve
      .description
      .description_data
      .iter()
      .map(|d| d.value.clone())
      .collect::<String>();
    let mut description = description.chars();
    html! {
      <>
      <div class="row g-2 align-items-center">
      <div class="col">
          <h2 class="page-title">
            {cve.id.clone()}
          </h2>
        </div>
        <div class="col-auto ms-auto d-print-none">
          <div class="d-flex">
            <ol class="breadcrumb breadcrumb-arrows" aria-label="breadcrumbs">
              <li class="breadcrumb-item">
                <Link<Route> classes={classes!("text-reset")} to={Route::CveList}>{"CVE"}</Link<Route>>
              </li>
              <li class="breadcrumb-item active" aria-current="page"><a href="#">{cve.id.clone()}</a></li>
            </ol>
          </div>
        </div>
      </div>
      <div class="card card-lg">
      <div class="card-header">
      <h3 class="card-title"><span style="float: left;line-height: 85%;width: .7em;font-size: 400%;font-family: georgia;">{description.next().unwrap_or_default()}</span><p>{description.collect::<String>()}</p></h3>
      </div>
      {self.cvss(cve.clone())}
      <div class="card-body">

      </div>
      </div>
      </>
    }
  }
  fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
    if first_render {
      ctx.link().send_message(Msg::Send);
    }
  }
}

impl CVEDetails {
  fn cvss(&self, cve: Cve) -> Html {
    let cvss_v3 = match ImpactMetricV3::from_str(&cve.cvss3_vector) {
      Ok(v3) => Some(v3),
      Err(_) => None,
    };
    html! {
      <>
      <div class="card-tabs">
      <ul class="nav nav-tabs" role="tablist">
      if let Some(v3) = cvss_v3{
        <li class="nav-item">
          <a href="#tabs-cvss3" class="nav-link active" data-bs-toggle="tab" aria-selected="true" role="tab">{format!("CVSS v{}",v3.cvss_v3.version.to_string())}</a>
        </li>
      }
        <li class="nav-item">
          <a href="#tabs-cvss2" class="nav-link" data-bs-toggle="tab">{"CVSS v2"}</a>
        </li>
      </ul>
        <div class="tab-content">
          <div class="tab-pane show active" id="tabs-cvss3">
            <CVSS3 vector={cve.cvss3_vector}/>
          </div>
          <div class="tab-pane" id="tabs-cvss2">
            <div>{"cvss v2"}</div>
          </div>
        </div>
      </div>
    </>
    }
  }
}
