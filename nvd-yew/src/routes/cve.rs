use crate::component::cvss_tags::{cvss2, cvss3};
use crate::component::{
  Accordion, CVEConfiguration, CVEConfigurationProps, CWEDetails, Comments, CVSS2, CVSS3,
};
use crate::console_log;
use crate::modules::cve::Cve;
use crate::services::cve::cve_details;
use crate::services::FetchState;
use std::collections::HashSet;
use yew::prelude::*;
use yew_router::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct CVEProps {
  pub id: String,
}

pub enum Msg {
  SetFetchState(FetchState<Cve>),
  Back,
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
      Msg::Back => {
        ctx.link().navigator().unwrap().back();
      }
    }
    false
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    let on_back = ctx.link().callback(|_event: MouseEvent| Msg::Back);
    if self.cve.is_none() {
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
    html! {
      <>
      <div class="row g-2 align-items-center">
      <div class="col">
          <h2 class="page-title">{cve.id.clone()}</h2>
      </div>
        <div class="col-auto ms-auto d-print-none">
          <div class="d-flex">
            <ol class="breadcrumb breadcrumb-arrows" aria-label="breadcrumbs">
              <li class="breadcrumb-item">
                <li class="breadcrumb-item active" aria-current="page" onclick={on_back}>
                    <span type="button" class="ti ti-external-link" href="#">{"CVE"}</span>
                </li>
              </li>
              <li class="breadcrumb-item active" aria-current="page"><a href="#">{cve.id.clone()}</a></li>
            </ol>
          </div>
        </div>
      </div>
      <div class="card card-lg">
      <div class="card-header">
      {self.description(cve.description.clone())}
      </div>
        {self.cvss(cve.clone())}
        {self.references(cve.references)}
        {self.weaknesses(cve.weaknesses.clone())}
        {self.configurations(cve.configurations)}
        <Comments/>
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
    let cvss_v31 = cve.metrics.base_metric_v31.inner();
    let cvss_v3 = cve.metrics.base_metric_v3.inner();
    let cvss_v2 = cve.metrics.base_metric_v2.inner();
    let active_v31: Vec<&str> = if cvss_v31.is_some() {
      vec!["tab-pane", "show", "active"]
    } else {
      vec!["tab-pane", "show"]
    };
    let active_v30: Vec<&str> = if cvss_v31.is_none() && cvss_v3.is_some() {
      vec!["tab-pane", "show", "active"]
    } else {
      vec!["tab-pane", "show"]
    };
    let active_v2: Vec<&str> = if cvss_v31.is_none() && cvss_v3.is_none() {
      vec!["tab-pane", "show", "active"]
    } else {
      vec!["tab-pane", "show"]
    };
    html! {
      <>
      <div class="card-tabs p-1">
      <ul class="nav nav-tabs p-1" role="tablist">
      if let Some(v3) = cvss_v31{
        <li class="nav-item">
          <a href="#tabs-cvss31" class="nav-link" data-bs-toggle="tab" aria-selected="true" role="tab">{format!("CVSS v{}",v3.cvss_v3.version.to_string())} {cvss3(cvss_v31)}</a>
        </li>
      }
      if let Some(v3) = cvss_v3{
        <li class="nav-item">
          <a href="#tabs-cvss30" class="nav-link" data-bs-toggle="tab" aria-selected="true" role="tab">{format!("CVSS v{}",v3.cvss_v3.version.to_string())} {cvss3(cvss_v3)}</a>
        </li>
      }
      if let Some(v2) = cvss_v2{
        <li class="nav-item">
          <a href="#tabs-cvss2" class="nav-link" data-bs-toggle="tab">{format!("CVSS v{}",v2.cvss_v2.version.to_string())} {cvss2(cvss_v2)}</a>
        </li>
      }
      </ul>
        <div class="tab-content">
        if let Some(v3) = cvss_v31{
          <div class={classes!(active_v31)} id="tabs-cvss31">
            <CVSS3 v3={Some(v3.clone())}/>
          </div>
        }
        if let Some(v3) = cvss_v3{
          <div class={classes!(active_v30)} id="tabs-cvss30">
            <CVSS3 v3={Some(v3.clone())}/>
          </div>
        }
        if let Some(v2) = cvss_v2{
          <div class={classes!(active_v2)} id="tabs-cvss2">
            <CVSS2 v2={Some(v2.clone())}/>
          </div>
        }
        </div>
      </div>
    </>
    }
  }
  fn description(&self, description_data: Vec<nvd_cves::v4::Description>) -> Html {
    let description = description_data
      .iter()
      .map(|d| d.value.clone())
      .collect::<String>();
    let mut description = description.chars();
    html! {
      <h3 class="card-title"><span style="fonts-weight:400;text-shadow:none;display:block;float:left;line-height:36px;width:.7em;fonts-size:3.1em;fonts-family:georgia;margin-right:6px;">{description.next().unwrap_or_default()}</span>{description.collect::<String>()}</h3>
    }
  }
  fn references(&self, reference: Vec<nvd_cves::v4::Reference>) -> Html {
    html! {
      <Accordion name={"References"}>
      <div class="table-responsive">
        <table class="table table-vcenter card-table table-striped">
          <thead>
            <tr>
              <th>{"Link"}</th>
              <th>{"Resource"}</th>
              <th>{"Tags"}</th>
            </tr>
          </thead>
          <tbody>
          {reference.into_iter().map(|r|{
            html!{
              <tr>
              <td><i class="ti ti-external-link"></i><a href={r.url.clone()} target="_blank">{r.url}</a></td>
              <td class="text-dark">
                {r.source}
              </td>
              <td class="text-secondary">
              <div class="badges-list">
                {r.tags.into_iter().map(|t|{html!(<span class="badge bg-blue text-blue-fg">{t}</span>)}).collect::<Html>()}
              </div>
              </td>
            </tr>
            }
          }).collect::<Html>()}
          </tbody>
        </table>
      </div>
      </Accordion>
    }
  }
  fn configurations(&self, configuration: Vec<nvd_cves::v4::configurations::Node>) -> Html {
    let p = CVEConfigurationProps {
      props: configuration.clone(),
    };
    html! {<CVEConfiguration ..p.clone()/>}
  }

  fn weaknesses(&self, ws: Vec<nvd_cves::v4::Weaknesses>) -> Html {
    // CVE-2006-5757有多个cwe
    let ws_set = ws
      .into_iter()
      .flat_map(|w| w.description)
      .map(|d| d.value)
      .collect::<HashSet<String>>();
    html! {
      <Accordion name={"Weaknesses"}>
      {ws_set.into_iter().map(|d|{
                html!{<CWEDetails id={d}/>}
            }).collect::<Html>()}
      </Accordion>
    }
  }
}
