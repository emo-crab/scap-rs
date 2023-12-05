use crate::component::TooltipPopover;
use cvss::metric::{Help, Worth};
use cvss::severity::{SeverityType, SeverityTypeV2};
use yew::prelude::*;

pub fn cvss2(metric: Option<&cvss::v2::ImpactMetricV2>) -> Html {
  let mut score = String::from("N/A");
  let severity_class = match metric {
    None => "bg-secondary",
    Some(m) => {
      score = format!("{} {}", m.cvss_v2.base_score, m.severity);
      match m.severity {
        SeverityTypeV2::None => "bg-secondary",
        SeverityTypeV2::Low => "bg-info",
        SeverityTypeV2::Medium => "bg-warning",
        SeverityTypeV2::High => "bg-danger",
      }
    }
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score}</b></span>)
}
pub fn cvss3(metric: Option<&cvss::v3::ImpactMetricV3>) -> Html {
  let mut score = String::from("N/A");
  let severity_class = match metric {
    None => "bg-secondary",
    Some(m) => {
      score = format!(
        "{} {}",
        m.cvss_v3.base_score,
        m.cvss_v3.base_severity
      );
      match m.cvss_v3.base_severity {
        SeverityType::None => "bg-secondary",
        SeverityType::Low => "bg-info",
        SeverityType::Medium => "bg-warning",
        SeverityType::High => "bg-danger",
        SeverityType::Critical => "bg-dark",
      }
    }
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score}</b></span>)
}
pub enum V3Card {
  AV(cvss::v3::attack_vector::AttackVectorType),
  AC(cvss::v3::attack_complexity::AttackComplexityType),
  PR(cvss::v3::privileges_required::PrivilegesRequiredType),
  UI(cvss::v3::user_interaction::UserInteractionType),
  C(cvss::v3::impact_metrics::ConfidentialityImpactType),
  I(cvss::v3::impact_metrics::IntegrityImpactType),
  A(cvss::v3::impact_metrics::AvailabilityImpactType),
  S(cvss::v3::scope::ScopeType),
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
        cvss::v3::attack_vector::AttackVectorType::Network => "ti-network",
        cvss::v3::attack_vector::AttackVectorType::AdjacentNetwork => "ti-cloud-network",
        cvss::v3::attack_vector::AttackVectorType::Local => "ti-current-location",
        cvss::v3::attack_vector::AttackVectorType::Physical => "ti-body-scan",
      },
      V3Card::AC(ac) => match ac {
        cvss::v3::attack_complexity::AttackComplexityType::High => "ti-mood-unamused",
        cvss::v3::attack_complexity::AttackComplexityType::Low => "ti-mood-smile",
      },
      V3Card::PR(pr) => match pr {
        cvss::v3::privileges_required::PrivilegesRequiredType::High => "ti-lock-check",
        cvss::v3::privileges_required::PrivilegesRequiredType::Low => "ti-lock-pause",
        cvss::v3::privileges_required::PrivilegesRequiredType::None => "ti-lock-open",
      },
      V3Card::UI(ui) => match ui {
        cvss::v3::user_interaction::UserInteractionType::Required => "ti-user-plus",
        cvss::v3::user_interaction::UserInteractionType::None => "ti-user-check",
      },
      V3Card::C(c) => match c {
        cvss::v3::impact_metrics::ConfidentialityImpactType::High => "ti-eye",
        cvss::v3::impact_metrics::ConfidentialityImpactType::Low => "ti-eye-x",
        cvss::v3::impact_metrics::ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V3Card::I(i) => match i {
        cvss::v3::impact_metrics::IntegrityImpactType::High => "ti-menu-2",
        cvss::v3::impact_metrics::IntegrityImpactType::Low => "ti-menu-deep",
        cvss::v3::impact_metrics::IntegrityImpactType::None => "ti-menu",
      },
      V3Card::A(a) => match a {
        cvss::v3::impact_metrics::AvailabilityImpactType::High => "ti-lock-access-off",
        cvss::v3::impact_metrics::AvailabilityImpactType::Low => "ti-lock-x",
        cvss::v3::impact_metrics::AvailabilityImpactType::None => "ti-lock-access",
      },
      V3Card::S(s) => match s {
        cvss::v3::scope::ScopeType::Unchanged => "ti-replace-off",
        cvss::v3::scope::ScopeType::Changed => "ti-replace",
      },
    }
  }
}

pub enum V2Card {
  AV(cvss::v2::access_vector::AccessVectorType),
  AC(cvss::v2::access_complexity::AccessComplexityType),
  AU(cvss::v2::authentication::AuthenticationType),
  C(cvss::v2::impact_metrics::ConfidentialityImpactType),
  I(cvss::v2::impact_metrics::IntegrityImpactType),
  A(cvss::v2::impact_metrics::AvailabilityImpactType),
}

impl From<V2Card> for yew::virtual_dom::VNode {
  fn from(value: V2Card) -> Self {
    value.to_html()
  }
}
impl V2Card {
  fn help(&self) -> Help {
    match self {
      V2Card::AV(av) => av.metric_help(),
      V2Card::AC(ac) => ac.metric_help(),
      V2Card::AU(pr) => pr.metric_help(),
      V2Card::C(c) => c.metric_help(),
      V2Card::I(i) => i.metric_help(),
      V2Card::A(a) => a.metric_help(),
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
      V2Card::AV(v) => ("Access Vector", format!("{:?}", v)),
      V2Card::AC(v) => ("Access Complexity", format!("{:?}", v)),
      V2Card::AU(v) => ("Authentication", format!("{:?}", v)),
      V2Card::C(v) => ("Confidentiality Impact", format!("{:?}", v)),
      V2Card::I(v) => ("Integrity Impact", format!("{:?}", v)),
      V2Card::A(v) => ("Availability Impact", format!("{:?}", v)),
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
      V2Card::AV(av) => match av {
        cvss::v2::access_vector::AccessVectorType::Network => "ti-network",
        cvss::v2::access_vector::AccessVectorType::AdjacentNetwork => "ti-cloud-network",
        cvss::v2::access_vector::AccessVectorType::Local => "ti-current-location",
      },
      V2Card::AC(ac) => match ac {
        cvss::v2::access_complexity::AccessComplexityType::High => "ti-mood-unamused",
        cvss::v2::access_complexity::AccessComplexityType::Medium => "ti-mood-unamused",
        cvss::v2::access_complexity::AccessComplexityType::Low => "ti-mood-smile",
      },
      V2Card::AU(pr) => match pr {
        cvss::v2::authentication::AuthenticationType::Multiple => "ti-lock-check",
        cvss::v2::authentication::AuthenticationType::Single => "ti-lock-pause",
        cvss::v2::authentication::AuthenticationType::None => "ti-lock-open",
      },
      V2Card::C(c) => match c {
        cvss::v2::impact_metrics::ConfidentialityImpactType::Complete => "ti-eye",
        cvss::v2::impact_metrics::ConfidentialityImpactType::Partial => "ti-eye-x",
        cvss::v2::impact_metrics::ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V2Card::I(i) => match i {
        cvss::v2::impact_metrics::IntegrityImpactType::Complete => "ti-menu-2",
        cvss::v2::impact_metrics::IntegrityImpactType::Partial => "ti-menu-deep",
        cvss::v2::impact_metrics::IntegrityImpactType::None => "ti-menu",
      },
      V2Card::A(a) => match a {
        cvss::v2::impact_metrics::AvailabilityImpactType::Complete => "ti-lock-access-off",
        cvss::v2::impact_metrics::AvailabilityImpactType::Partial => "ti-lock-x",
        cvss::v2::impact_metrics::AvailabilityImpactType::None => "ti-lock-access",
      },
    }
  }
}
