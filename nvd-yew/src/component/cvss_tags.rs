use cvss::severity::{SeverityTypeV2, SeverityTypeV3};
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
  let severity = cvss::severity::SeverityTypeV3::from(score);
  let severity_class = match severity {
    SeverityTypeV3::None => "bg-secondary",
    SeverityTypeV3::Low => "bg-info",
    SeverityTypeV3::Medium => "bg-warning",
    SeverityTypeV3::High => "bg-danger",
    SeverityTypeV3::Critical => "bg-dark",
  };
  let score_str = if score == 0.0 {
    String::from("N/A")
  } else {
    format!("{} {}", score, severity)
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="font-size:larger">{score_str}</b></span>)
}
pub enum V3Card {
  AttackVectorType(AttackVectorType),
  AttackComplexityType(AttackComplexityType),
  PrivilegesRequiredType(PrivilegesRequiredType),
  UserInteractionType(UserInteractionType),
  ConfidentialityImpactType(ConfidentialityImpactType),
  IntegrityImpactType(IntegrityImpactType),
  AvailabilityImpactType(AvailabilityImpactType),
  ScopeType(ScopeType),
}
pub fn cvss_v3_card(value: V3Card) -> Html {
  let (name, value, class_str) = match value {
    V3Card::AttackVectorType(av) => {
      let class_str = match av {
        AttackVectorType::Network => "bg-danger",
        AttackVectorType::AdjacentNetwork => "bg-warning",
        AttackVectorType::Local => "bg-info",
        AttackVectorType::Physical => "bg-secondary",
      };
      ("Attack Vector", format!("{:?}", av), class_str)
    }
    V3Card::AttackComplexityType(ac) => {
      let class_str = match ac {
        AttackComplexityType::High => "bg-warning",
        AttackComplexityType::Low => "bg-danger",
      };
      ("Attack Complexity", format!("{:?}", ac), class_str)
    }
    V3Card::PrivilegesRequiredType(pr) => {
      let class_str = match pr {
        PrivilegesRequiredType::High => "bg-info",
        PrivilegesRequiredType::Low => "bg-warning",
        PrivilegesRequiredType::None => "bg-danger",
      };
      ("Privileges Required", format!("{:?}", pr), class_str)
    }
    V3Card::UserInteractionType(ui) => {
      let class_str = match ui {
        UserInteractionType::Required => "bg-warning",
        UserInteractionType::None => "bg-danger",
      };
      ("User Interaction", format!("{:?}", ui), class_str)
    }
    V3Card::ConfidentialityImpactType(c) => {
      let class_str = match c {
        ConfidentialityImpactType::High => "bg-danger",
        ConfidentialityImpactType::Low => "bg-warning",
        ConfidentialityImpactType::None => "bg-info",
      };
      ("Confidentiality Impact", format!("{:?}", c), class_str)
    }
    V3Card::IntegrityImpactType(i) => {
      let class_str = match i {
        IntegrityImpactType::High => "bg-danger",
        IntegrityImpactType::Low => "bg-warning",
        IntegrityImpactType::None => "bg-info",
      };
      ("Integrity Impact", format!("{:?}", i), class_str)
    }
    V3Card::AvailabilityImpactType(a) => {
      let class_str = match a {
        AvailabilityImpactType::High => "bg-danger",
        AvailabilityImpactType::Low => "bg-warning",
        AvailabilityImpactType::None => "bg-info",
      };
      ("Availability Impact", format!("{:?}", a), class_str)
    }
    V3Card::ScopeType(s) => {
      let class_str = match s {
        ScopeType::Unchanged => "bg-warning",
        ScopeType::Changed => "bg-danger",
      };
      ("Scope", format!("{:?}", s), class_str)
    }
  };
  html! {
      <div class="justify-content-between align-items-start">
        <li class="card card-sm card-link card-link-pop">
          <div class={classes!(["card-status-start",class_str])}></div>
          <div class="card-header p-2"><h5 class="card-title">{name}</h5>
          <div class="card-actions">
            <span class={classes!(["badge",class_str])}>{value}</span>
          </div>
          </div>
        </li>
      </div>
  }
}
