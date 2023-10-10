use cvss::v3::ImpactMetricV3;
use std::str::FromStr;
use yew::prelude::*;
#[derive(Default)]
pub struct CVSS3;
#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct Props {
  pub vector: String,
}
impl Component for CVSS3 {
  type Message = ();
  type Properties = Props;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let v3 = ImpactMetricV3::from_str(&ctx.props().vector).unwrap();
    let cvss_v3 = v3.cvss_v3.clone();
    let score = v3.cvss_v3.base_score;
    let version = v3.cvss_v3.version;
    let base_severity = v3.cvss_v3.base_severity.to_string();
    let exploitability_score = v3.exploitability_score;
    let impact_score = v3.impact_score;
    html! {
        <>
        <div class="row">
          <div class="col-md-4">
            <div class="card border-danger mb-3">
              <div class="card-body">
                <h3>{score}<sup style="font-size: 20px"> {"/10"}</sup></h3>
                <p class="card-text">{"CVSS v"}{version}{": "}<span class="badge text-bg-danger">{base_severity}</span></p>
            <div class="progress" role="progressbar" aria-label="score" aria-valuenow={score.to_string()} aria-valuemin="0" aria-valuemax="10">
              <div class="progress-bar bg-danger shadow-lg" style="width: 100%">{score}</div>
            </div>
              </div>
              <div class="card-footer text-bg-light text-center text-muted">
                <a href="https://www.first.org/cvss/specification-document" target="_blank">
                    {"V3 Legend"} <i class="bi bi-arrow-up-right-square"></i></a>
              </div>
            </div>
            <div class="md-4">
            <input value={cvss_v3.to_string()} readonly=true type="text" class="form-control"/>
            </div>
            <div class="md-4">
            <ul class="list-group list-group-horizontal">
              <li class="list-group-item col-sm-6"><strong>{"Exploitability: "}</strong><span class="w-25"> {exploitability_score} </span></li>
              <li class="list-group-item col-sm-6"><strong>{"Impact: "}</strong><span class="w-25">{impact_score}</span></li>
            </ul>
            </div>
          </div>
          <div class="col-md-4">
            <div class="grid gap-3">
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.exploit_ability.attack_vector)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Attack Complexity"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.exploit_ability.attack_complexity)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Privileges Required"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.exploit_ability.privileges_required)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"User Interaction"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.exploit_ability.user_interaction)}</span>
            </li>
          </div>
          </div>
          <div class="col-md-4">
            <div class="grid gap-3">
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Scope"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.scope)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Confidentiality Impact"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.impact.confidentiality_impact)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Integrity Impact"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.impact.integrity_impact)}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger" style="margin-bottom: 10px;">
              {"Availability Impact"}
              <span class="badge text-bg-danger">{format!("{:#?}",cvss_v3.impact.availability_impact)}</span>
            </li>
          </div>
          </div>
    </div>
    // <div class="row">
    //     <div class="col-md-4">
    //         <div class="small-box bg-critical">
    //             <div class="inner">
    //                 <h3>{"9.8"}<sup style="font-size: 20px">{" /10"}</sup></h3>
    //                 <p>{"CVSS v3.0 : CRITICAL"}</p>
    //             </div>
    //             <div class="icon">
    //                 <i class="ion ion-stats-bars"></i>
    //             </div>
    //             <a href="https://www.first.org/cvss/specification-document" target="_blank" class="small-box-footer">
    //                 {"V3 Legend "}<i class="fa fa-arrow-circle-right"></i>
    //             </a>
    //         </div>
    //         <p><strong>{"Vector :"}</strong> </p>
    //         <p><strong>{"Exploitability :"}</strong> {"3.9 / "}<strong>{"Impact:"}</strong> {"5.9"}</p>
    //     </div>
    //
    //     <div class="col-md-4">
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Attack Vector"}
    //                         <span class="pull-right label label-danger">{"NETWORK"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Attack Complexity"}
    //                         <span class="pull-right label label-danger">{"LOW"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Privileges Required"}
    //                         <span class="pull-right label label-danger">{"NONE"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"User Interaction"}
    //                         <span class="pull-right label label-danger">{"NONE"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //     </div>
    //     <div class="col-md-4">
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Confidentiality Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Integrity Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Availability Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Scope"}
    //                         <span class="pull-right label label-default">{"UNCHANGED"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //     </div>
    // </div>
        </>
        }
  }
}
