use crate::component::TooltipPopover;
use cvss::metric::{Help, Worth};
use cvss::severity::{SeverityType, SeverityTypeV2};
use cvss::v3::attack_complexity::AttackComplexityType;
use cvss::v3::attack_vector::AttackVectorType;
use cvss::v3::impact_metrics::{
  AvailabilityImpactType, ConfidentialityImpactType, IntegrityImpactType,
};
use cvss::v3::privileges_required::PrivilegesRequiredType;
use cvss::v3::scope::ScopeType;
use cvss::v3::user_interaction::UserInteractionType;
use yew::prelude::*;

pub fn cvss2(score: f32) -> Html {
  let severity = cvss::severity::SeverityTypeV2::from(score);
  let severity_class = match severity {
    SeverityTypeV2::None => "bg-secondary",
    SeverityTypeV2::Low => "bg-info",
    SeverityTypeV2::Medium => "bg-warning",
    SeverityTypeV2::High => "bg-danger",
  };
  let score_str = if score == 0.0 {
    String::from("N/A")
  } else {
    score.to_string()
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score_str}</b></span>)
}
pub fn cvss3(score: f32) -> Html {
  let severity = cvss::severity::SeverityType::from(score);
  let severity_class = match severity {
    SeverityType::None => "bg-secondary",
    SeverityType::Low => "bg-info",
    SeverityType::Medium => "bg-warning",
    SeverityType::High => "bg-danger",
    SeverityType::Critical => "bg-dark",
  };
  let score_str = if score == 0.0 {
    String::from("N/A")
  } else {
    format!("{} {}", score, severity)
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score_str}</b></span>)
}
pub enum V3Card {
  AV(AttackVectorType),
  AC(AttackComplexityType),
  PR(PrivilegesRequiredType),
  UI(UserInteractionType),
  C(ConfidentialityImpactType),
  I(IntegrityImpactType),
  A(AvailabilityImpactType),
  S(ScopeType),
}

impl From<V3Card> for yew::virtual_dom::VNode {
  fn from(value: V3Card) -> Self {
    value.to_html()
  }
}
impl V3Card {
  fn help(&self) -> Help {
    match self {
      V3Card::AV(av) => av.metric_help(),
      V3Card::AC(ac) => ac.metric_help(),
      V3Card::PR(pr) => pr.metric_help(),
      V3Card::UI(ui) => ui.metric_help(),
      V3Card::C(c) => c.metric_help(),
      V3Card::I(i) => i.metric_help(),
      V3Card::A(a) => a.metric_help(),
      V3Card::S(s) => s.metric_help(),
    }
  }
  fn color(&self, worth: &Worth) -> &'static str {
    match worth {
      Worth::Worst => "bg-danger",
      Worth::Worse => "bg-warning",
      Worth::Bad => "bg-info",
      Worth::Good => "bg-secondary",
    }
  }
  pub fn to_html(&self) -> Html {
    let (name, value) = match self {
      V3Card::AV(v) => ("Attack Vector", format!("{:?}", v)),
      V3Card::AC(v) => ("Attack Complexity", format!("{:?}", v)),
      V3Card::PR(v) => ("Privileges Required", format!("{:?}", v)),
      V3Card::UI(v) => ("User Interaction", format!("{:?}", v)),
      V3Card::C(v) => ("Confidentiality Impact", format!("{:?}", v)),
      V3Card::I(v) => ("Integrity Impact", format!("{:?}", v)),
      V3Card::A(v) => ("Availability Impact", format!("{:?}", v)),
      V3Card::S(v) => ("Scope", format!("{:?}", v)),
    };
    let h = self.help();
    let icon = self.icon();
    let class_str = self.color(&h.worth);
    let des = h.des;
    html! {
        <div class="justify-content-between align-items-start">
          <li class="card card-sm card-link card-link-pop">
            <div class={classes!(["card-status-start",class_str])}></div>
            <div class="card-header p-2"><h5 class="card-title">{name}</h5>
            <div class="card-actions">
            <TooltipPopover
              toggle={"toggle"}
              placement={"top"}
              content={des}>
              <span class={classes!(["badge",class_str])}>
                <i class={classes!( ["ti",icon])}></i>{value}
              </span>
            </TooltipPopover>
            </div>
            </div>
          </li>
        </div>
    }
  }
  fn icon(&self) -> &'static str {
    match self {
      V3Card::AV(av) => match av {
        AttackVectorType::Network => "ti-network",
        AttackVectorType::AdjacentNetwork => "ti-cloud-network",
        AttackVectorType::Local => "ti-current-location",
        AttackVectorType::Physical => "ti-body-scan",
      },
      V3Card::AC(ac) => match ac {
        AttackComplexityType::High => "ti-mood-unamused",
        AttackComplexityType::Low => "ti-mood-smile",
      },
      V3Card::PR(pr) => match pr {
        PrivilegesRequiredType::High => "ti-lock-check",
        PrivilegesRequiredType::Low => "ti-lock-pause",
        PrivilegesRequiredType::None => "ti-lock-open",
      },
      V3Card::UI(ui) => match ui {
        UserInteractionType::Required => "ti-user-plus",
        UserInteractionType::None => "ti-user-check",
      },
      V3Card::C(c) => match c {
        ConfidentialityImpactType::High => "ti-eye",
        ConfidentialityImpactType::Low => "ti-eye-x",
        ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V3Card::I(i) => match i {
        IntegrityImpactType::High => "ti-menu-2",
        IntegrityImpactType::Low => "ti-menu-deep",
        IntegrityImpactType::None => "ti-menu",
      },
      V3Card::A(a) => match a {
        AvailabilityImpactType::High => "ti-lock-access-off",
        AvailabilityImpactType::Low => "ti-lock-x",
        AvailabilityImpactType::None => "ti-lock-access",
      },
      V3Card::S(s) => match s {
        ScopeType::Unchanged => "ti-replace-off",
        ScopeType::Changed => "ti-replace",
      },
    }
  }
}
