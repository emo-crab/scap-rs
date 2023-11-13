use cvss::metric::{Help, Worth};
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

impl V3Card {
  fn help(&self) -> Help {
    match self {
      V3Card::AttackVectorType(av) => av.metric_help(),
      V3Card::AttackComplexityType(ac) => ac.metric_help(),
      V3Card::PrivilegesRequiredType(pr) => pr.metric_help(),
      V3Card::UserInteractionType(ui) => ui.metric_help(),
      V3Card::ConfidentialityImpactType(c) => c.metric_help(),
      V3Card::IntegrityImpactType(i) => i.metric_help(),
      V3Card::AvailabilityImpactType(a) => a.metric_help(),
      V3Card::ScopeType(s) => s.metric_help(),
    }
  }
  fn color(&self, worth: &Worth) -> &str {
    match worth {
      Worth::Worst => "bg-danger",
      Worth::Worse => "bg-warning",
      Worth::Bad => "bg-info",
      Worth::Good => "bg-secondary",
    }
  }
  fn name(&self) -> &str {
    match self {
      V3Card::AttackVectorType(_) => "Attack Vector",
      V3Card::AttackComplexityType(_) => "Attack Complexity",
      V3Card::PrivilegesRequiredType(_) => "Privileges Required",
      V3Card::UserInteractionType(_) => "User Interaction",
      V3Card::ConfidentialityImpactType(_) => "Confidentiality Impact",
      V3Card::IntegrityImpactType(_) => "Integrity Impact",
      V3Card::AvailabilityImpactType(_) => "Availability Impact",
      V3Card::ScopeType(_) => "Scope",
    }
  }
  fn icon(&self) -> &str {
    match self {
      V3Card::AttackVectorType(av) => match av {
        AttackVectorType::Network => "ti-network",
        AttackVectorType::AdjacentNetwork => "ti-cloud-network",
        AttackVectorType::Local => "ti-current-location",
        AttackVectorType::Physical => "ti-body-scan",
      },
      V3Card::AttackComplexityType(ac) => match ac {
        AttackComplexityType::High => "ti-mood-unamused",
        AttackComplexityType::Low => "ti-mood-smile",
      },
      V3Card::PrivilegesRequiredType(pr) => match pr {
        PrivilegesRequiredType::High => "ti-lock-check",
        PrivilegesRequiredType::Low => "ti-lock-pause",
        PrivilegesRequiredType::None => "ti-lock-open",
      },
      V3Card::UserInteractionType(ui) => match ui {
        UserInteractionType::Required => "ti-user-plus",
        UserInteractionType::None => "ti-user-check",
      },
      V3Card::ConfidentialityImpactType(c) => match c {
        ConfidentialityImpactType::High => "ti-eye",
        ConfidentialityImpactType::Low => "ti-eye-x",
        ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V3Card::IntegrityImpactType(i) => match i {
        IntegrityImpactType::High => "ti-menu-2",
        IntegrityImpactType::Low => "ti-menu-deep",
        IntegrityImpactType::None => "ti-menu",
      },
      V3Card::AvailabilityImpactType(a) => match a {
        AvailabilityImpactType::High => "ti-lock-access-off",
        AvailabilityImpactType::Low => "ti-lock-x",
        AvailabilityImpactType::None => "ti-lock-access",
      },
      V3Card::ScopeType(s) => match s {
        ScopeType::Unchanged => "ti-replace-off",
        ScopeType::Changed => "ti-replace",
      },
    }
  }
}

pub fn cvss_v3_card(value: V3Card) -> Html {
  let (name, value, class_str, icon) = match value {
    V3Card::AttackVectorType(av) => {
      let help = av.metric_help();
      let (class_str, icon) = match av {
        AttackVectorType::Network => ("bg-danger", "ti-network"),
        AttackVectorType::AdjacentNetwork => ("bg-warning", "ti-cloud-network"),
        AttackVectorType::Local => ("bg-info", "ti-current-location"),
        AttackVectorType::Physical => ("bg-secondary", "ti-body-scan"),
      };
      ("Attack Vector", format!("{:?}", av), class_str, icon)
    }
    V3Card::AttackComplexityType(ac) => {
      let (class_str, icon) = match ac {
        AttackComplexityType::High => ("bg-warning", "ti-mood-unamused"),
        AttackComplexityType::Low => ("bg-danger", "ti-mood-smile"),
      };
      ("Attack Complexity", format!("{:?}", ac), class_str, icon)
    }
    V3Card::PrivilegesRequiredType(pr) => {
      let (class_str, icon) = match pr {
        PrivilegesRequiredType::High => ("bg-info", "ti-lock-check"),
        PrivilegesRequiredType::Low => ("bg-warning", "ti-lock-pause"),
        PrivilegesRequiredType::None => ("bg-danger", "ti-lock-open"),
      };
      ("Privileges Required", format!("{:?}", pr), class_str, icon)
    }
    V3Card::UserInteractionType(ui) => {
      let (class_str, icon) = match ui {
        UserInteractionType::Required => ("bg-warning", "ti-user-plus"),
        UserInteractionType::None => ("bg-danger", "ti-user-check"),
      };
      ("User Interaction", format!("{:?}", ui), class_str, icon)
    }
    V3Card::ConfidentialityImpactType(c) => {
      let (class_str, icon) = match c {
        ConfidentialityImpactType::High => ("bg-danger", "ti-eye"),
        ConfidentialityImpactType::Low => ("bg-warning", "ti-eye-x"),
        ConfidentialityImpactType::None => ("bg-info", "ti-eye-closed"),
      };
      (
        "Confidentiality Impact",
        format!("{:?}", c),
        class_str,
        icon,
      )
    }
    V3Card::IntegrityImpactType(i) => {
      let (class_str, icon) = match i {
        IntegrityImpactType::High => ("bg-danger", "ti-menu-2"),
        IntegrityImpactType::Low => ("bg-warning", "ti-menu-deep"),
        IntegrityImpactType::None => ("bg-info", "ti-menu"),
      };
      ("Integrity Impact", format!("{:?}", i), class_str, icon)
    }
    V3Card::AvailabilityImpactType(a) => {
      let (class_str, icon) = match a {
        AvailabilityImpactType::High => ("bg-danger", "ti-lock-access-off"),
        AvailabilityImpactType::Low => ("bg-warning", "ti-lock-x"),
        AvailabilityImpactType::None => ("bg-info", "ti-lock-access"),
      };
      ("Availability Impact", format!("{:?}", a), class_str, icon)
    }
    V3Card::ScopeType(s) => {
      let (class_str, icon) = match s {
        ScopeType::Unchanged => ("bg-warning", "ti-replace-off"),
        ScopeType::Changed => ("bg-danger", "ti-replace"),
      };
      ("Scope", format!("{:?}", s), class_str, icon)
    }
  };
  html! {
      <div class="justify-content-between align-items-start">
        <li class="card card-sm card-link card-link-pop">
          <div class={classes!(["card-status-start",class_str])}></div>
          <div class="card-header p-2"><h5 class="card-title">{name}</h5>
          <div class="card-actions">
            <span class={classes!(["badge",class_str])}><i class={classes!( ["ti",icon])}></i>{value}</span>
          </div>
          </div>
        </li>
      </div>
  }
}
