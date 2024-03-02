use crate::component::cvss_tags::V2CardTag;
use crate::component::use_translation;
use crate::component::{V2Card, V3Card, V3CardTag};
use nvd_cvss::v2::ImpactMetricV2;
use nvd_cvss::v3::ImpactMetricV3;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct V3Props {
  pub v3: Option<ImpactMetricV3>,
}
#[function_component]
pub fn CVSS3(props: &V3Props) -> Html {
  let V3Props { v3, .. } = props;
  let i18n = use_translation();
  let v3 = v3.clone().unwrap();
  let cvss_v3 = v3.cvss_v3.clone();
  let score = v3.cvss_v3.base_score;
  let source = v3.source.clone();
  let who = v3.r#type.clone();
  let exploit_ability_score = round_score(v3.exploitability_score);
  let impact_score = round_score(v3.impact_score);
  html! {
      <>
    <div class="row">
      <div class="col-md-4">
        <div class="md-4">
        <div class="card border-danger mb-3">
        <div class="card-body p-2">
        <input value={cvss_v3.to_string()} readonly=true type="text" class="form-control"/>
        </div>
        <div class="md-4">
        <ul class="list-group list-group-horizontal">
          <li class="list-group-item col-sm-6"><strong>{i18n.t("ExploitAbility")}</strong>{exploit_ability_score}</li>
          <li class="list-group-item col-sm-6"><strong>{i18n.t("Impact")}</strong>{impact_score}</li>
        </ul>
      </div>
      </div>
      <div class="card-footer text-bg-light text-center text-muted p-2">
          <span class="badge bg-red">{format!("{:?}",who)}</span>
          <span class="badge bg-blue">{source}</span>
      </div>
      <div class="progress progress-sm card-progress">
        <div class="progress-bar" style={format!( "width: {}%",(score*10.0))} role="progressbar" aria-valuenow={score.to_string()} aria-valuemin="0" aria-valuemax="10">
          <span class="visually-hidden">{score.to_string()}</span>
        </div>
      </div>
      </div>
      </div>
      <div class="col-md-4">
        <V3CardTag props={ V3Card::AV(cvss_v3.exploit_ability.attack_vector)}/>
        <V3CardTag props={V3Card::AC(cvss_v3.exploit_ability.attack_complexity)}/>
        <V3CardTag props={V3Card::PR(cvss_v3.exploit_ability.privileges_required)}/>
        <V3CardTag props={V3Card::UI(cvss_v3.exploit_ability.user_interaction)}/>
      </div>
      <div class="col-md-4">
        <V3CardTag props={V3Card::S(cvss_v3.scope)}/>
        <V3CardTag props={V3Card::C(cvss_v3.impact.confidentiality_impact)}/>
        <V3CardTag props={V3Card::I(cvss_v3.impact.integrity_impact)}/>
        <V3CardTag props={V3Card::A(cvss_v3.impact.availability_impact)}/>
      </div>
    </div>
    </>
  }
}

// 小数点后两位四舍五入
fn round_score(score: f32) -> String {
  let s = (score * 10.0).round() / 10.0;
  format!("{:.1}", s)
}

#[derive(Default)]
pub struct CVSS2;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct V2Props {
  pub v2: Option<ImpactMetricV2>,
}

impl Component for CVSS2 {
  type Message = ();
  type Properties = V2Props;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let v2 = ctx.props().v2.clone().unwrap();
    let who = v2.r#type.clone();
    let source = v2.source.clone();
    let cvss_v2 = v2.cvss_v2.clone();
    let score = v2.cvss_v2.base_score;
    let exploit_ability_score = round_score(v2.exploitability_score);
    let impact_score = round_score(v2.impact_score);
    html! {
        <>
      <div class="row">
        <div class="col-md-4">
          <div class="md-4">
          <div class="card border-danger mb-3">
          <div class="card-body p-2">
          <input value={cvss_v2.to_string()} readonly=true type="text" class="form-control"/>
          </div>
          <div class="md-4">
          <ul class="list-group list-group-horizontal">
            <li class="list-group-item col-sm-6"><strong>{"ExploitAbility:"}</strong>{exploit_ability_score}</li>
            <li class="list-group-item col-sm-6"><strong>{"Impact:"}</strong>{impact_score}</li>
          </ul>
        </div>
        </div>
        <div class="card-footer text-bg-light text-center text-muted p-2">
            <span class="badge bg-red">{format!("{:?}",who)}</span>
            <span class="badge bg-blue">{source}</span>
        </div>
        <div class="progress progress-sm card-progress">
          <div class="progress-bar" style={format!( "width: {}%",(score*10.0))} role="progressbar" aria-valuenow={score.to_string()} aria-valuemin="0" aria-valuemax="10">
            <span class="visually-hidden">{score.to_string()}</span>
          </div>
        </div>
        </div>
        </div>
        <div class="col-md-4">
          <V2CardTag props={V2Card::AV(cvss_v2.access_vector)}/>
          <V2CardTag props={V2Card::AC(cvss_v2.access_complexity)}/>
          <V2CardTag props={V2Card::AU(cvss_v2.authentication)}/>
        </div>
        <div class="col-md-4">
          <V2CardTag props={V2Card::C(cvss_v2.confidentiality_impact)}/>
          <V2CardTag props={V2Card::I(cvss_v2.integrity_impact)}/>
          <V2CardTag props={V2Card::A(cvss_v2.availability_impact)}/>
        </div>
      </div>
      </>
    }
  }
}
