use crate::component::cvss_tags::V3Card;
use cvss::v3::ImpactMetricV3;
use yew::prelude::*;

#[derive(Default)]
pub struct CVSS3;
#[derive(Clone, Debug, PartialEq, Properties)]
pub struct Props {
  pub v3: Option<ImpactMetricV3>,
}
impl Component for CVSS3 {
  type Message = ();
  type Properties = Props;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let v3 = ctx.props().v3.clone().unwrap();
    let cvss_v3 = v3.cvss_v3.clone();
    let score = v3.cvss_v3.base_score;
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
            <li class="list-group-item col-sm-6"><strong>{"ExploitAbility:"}</strong>{exploit_ability_score}</li>
            <li class="list-group-item col-sm-6"><strong>{"Impact:"}</strong>{impact_score}</li>
          </ul>
        </div>
        </div>
        <div class="card-footer text-bg-light text-center text-muted p-2">
          <a href="https://www.first.org/cvss/specification-document" target="_blank">
              {"V3 Legend"} <i class="ti ti-external-link"></i></a>
        </div>
        <div class="progress progress-sm card-progress">
          <div class="progress-bar" style={format!( "width: {}%",(score*10.0).to_string())} role="progressbar" aria-valuenow={score.to_string()} aria-valuemin="0" aria-valuemax="10">
            <span class="visually-hidden">{score.to_string()}</span>
          </div>
        </div>
        </div>
        </div>
        <div class="col-md-4">
          {V3Card::AttackVectorType(cvss_v3.exploit_ability.attack_vector)}
          {V3Card::AttackComplexityType(cvss_v3.exploit_ability.attack_complexity)}
          {V3Card::PrivilegesRequiredType(cvss_v3.exploit_ability.privileges_required)}
          {V3Card::UserInteractionType(cvss_v3.exploit_ability.user_interaction)}
        </div>
        <div class="col-md-4">
          {V3Card::ScopeType(cvss_v3.scope)}
          {V3Card::ConfidentialityImpactType(cvss_v3.impact.confidentiality_impact)}
          {V3Card::IntegrityImpactType(cvss_v3.impact.integrity_impact)}
          {V3Card::AvailabilityImpactType(cvss_v3.impact.availability_impact)}
        </div>
      </div>
      </>
    }
  }
}
// 小数点后两位四舍五入
fn round_score(score: f32) -> String {
  let s = (score * 10.0).round() / 10.0;
  format!("{:.1}", s)
}
