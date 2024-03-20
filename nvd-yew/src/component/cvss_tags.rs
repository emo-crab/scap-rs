use crate::component::{MessageContext, TooltipPopover};
use nvd_cves::impact::ImpactMetrics;
use nvd_cvss::metric::{Help, Worth};
use nvd_cvss::severity::{SeverityType, SeverityTypeV2};
use yew::prelude::*;

pub fn cvss(metrics: &ImpactMetrics) -> Html {
  let na = metrics.base_metric_v31.inner().is_none()
    && metrics.base_metric_v3.inner().is_none()
    && metrics.base_metric_v2.inner().is_none();
  html! {
    <>
    if let Some(v31)=metrics.base_metric_v31.inner(){
      {cvss3(Some(v31))}
    }
    if let Some(v30)=metrics.base_metric_v3.inner(){
      {cvss3(Some(v30))}
    }
    if let Some(v2)=metrics.base_metric_v2.inner(){
      {cvss2(Some(v2))}
    }
    if na{
      <span class="badge bg-secondary"><b style="fonts-size:larger">{"N/A"}</b></span>
    }
    </>
  }
}

pub fn cvss2(metric: Option<&nvd_cvss::v2::ImpactMetricV2>) -> Html {
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
  html!(<span class={classes!(["badge",severity_class])}><b style="fonts-size:larger">{score}</b></span>)
}
pub fn cvss3(metric: Option<&nvd_cvss::v3::ImpactMetricV3>) -> Html {
  let mut score = String::from("N/A");
  let severity_class = match metric {
    None => "bg-secondary",
    Some(m) => {
      score = format!("{} {}", m.cvss_v3.base_score, m.cvss_v3.base_severity);
      match m.cvss_v3.base_severity {
        SeverityType::None => "bg-secondary",
        SeverityType::Low => "bg-info",
        SeverityType::Medium => "bg-warning",
        SeverityType::High => "bg-danger",
        SeverityType::Critical => "bg-dark",
      }
    }
  };
  html!(<span class={classes!(["badge",severity_class])}><b style="fonts-size:larger">{score}</b></span>)
}
#[derive(Clone, PartialEq)]
pub enum V3Card {
  AV(nvd_cvss::v3::attack_vector::AttackVectorType),
  AC(nvd_cvss::v3::attack_complexity::AttackComplexityType),
  PR(nvd_cvss::v3::privileges_required::PrivilegesRequiredType),
  UI(nvd_cvss::v3::user_interaction::UserInteractionType),
  C(nvd_cvss::v3::impact_metrics::ConfidentialityImpactType),
  I(nvd_cvss::v3::impact_metrics::IntegrityImpactType),
  A(nvd_cvss::v3::impact_metrics::AvailabilityImpactType),
  S(nvd_cvss::v3::scope::ScopeType),
}
pub enum Msg {
  Lang(MessageContext),
}
pub struct V3CardTag {
  inner: V3Card,
  i18n: MessageContext,
  _context_listener: ContextHandle<MessageContext>,
}
#[derive(PartialEq, Clone, Properties)]
pub struct V3CardTagProps {
  pub props: V3Card,
}
impl Component for V3CardTag {
  type Message = Msg;
  type Properties = V3CardTagProps;

  fn create(ctx: &Context<Self>) -> Self {
    let v3 = ctx.props().clone().props;
    let (i18n, lang) = ctx
      .link()
      .context::<MessageContext>(ctx.link().callback(Msg::Lang))
      .unwrap();
    Self {
      inner: v3,
      i18n,
      _context_listener: lang,
    }
  }
  fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::Lang(i18n) => {
        self.i18n = i18n;
        true
      }
    }
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    let (name, value) = match self.inner.clone() {
      V3Card::AV(v) => ("Attack Vector", format!("{:?}", v)),
      V3Card::AC(v) => ("Attack Complexity", format!("{:?}", v)),
      V3Card::PR(v) => ("Privileges Required", format!("{:?}", v)),
      V3Card::UI(v) => ("User Interaction", format!("{:?}", v)),
      V3Card::C(v) => ("Confidentiality Impact", format!("{:?}", v)),
      V3Card::I(v) => ("Integrity Impact", format!("{:?}", v)),
      V3Card::A(v) => ("Availability Impact", format!("{:?}", v)),
      V3Card::S(v) => ("Scope", format!("{:?}", v)),
    };
    let h = self.inner.help();
    let icon = self.inner.icon();
    let class_str = self.inner.color(&h.worth);
    let des = h.des;
    html! {
        <div class="justify-content-between align-items-start">
          <li class="card card-sm card-link card-link-pop">
            <div class={classes!(["card-status-start",class_str])}></div>
            <div class="card-header p-2"><h5 class="card-title">{self.i18n.t(name)}</h5>
            <div class="card-actions">
            <TooltipPopover
              toggle={"toggle"}
              placement={"top"}
              content={des}>
              <span class={classes!(["badge",class_str])}>
                <i class={classes!( ["ti",icon])}></i>{self.i18n.t(&value)}
              </span>
            </TooltipPopover>
            </div>
            </div>
          </li>
        </div>
    }
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
  fn icon(&self) -> &'static str {
    match self {
      V3Card::AV(av) => match av {
        nvd_cvss::v3::attack_vector::AttackVectorType::Network => "ti-network",
        nvd_cvss::v3::attack_vector::AttackVectorType::AdjacentNetwork => "ti-cloud-network",
        nvd_cvss::v3::attack_vector::AttackVectorType::Local => "ti-current-location",
        nvd_cvss::v3::attack_vector::AttackVectorType::Physical => "ti-body-scan",
      },
      V3Card::AC(ac) => match ac {
        nvd_cvss::v3::attack_complexity::AttackComplexityType::High => "ti-mood-unamused",
        nvd_cvss::v3::attack_complexity::AttackComplexityType::Low => "ti-mood-smile",
      },
      V3Card::PR(pr) => match pr {
        nvd_cvss::v3::privileges_required::PrivilegesRequiredType::High => "ti-lock-check",
        nvd_cvss::v3::privileges_required::PrivilegesRequiredType::Low => "ti-lock-pause",
        nvd_cvss::v3::privileges_required::PrivilegesRequiredType::None => "ti-lock-open",
      },
      V3Card::UI(ui) => match ui {
        nvd_cvss::v3::user_interaction::UserInteractionType::Required => "ti-user-plus",
        nvd_cvss::v3::user_interaction::UserInteractionType::None => "ti-user-check",
      },
      V3Card::C(c) => match c {
        nvd_cvss::v3::impact_metrics::ConfidentialityImpactType::High => "ti-eye",
        nvd_cvss::v3::impact_metrics::ConfidentialityImpactType::Low => "ti-eye-x",
        nvd_cvss::v3::impact_metrics::ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V3Card::I(i) => match i {
        nvd_cvss::v3::impact_metrics::IntegrityImpactType::High => "ti-menu-2",
        nvd_cvss::v3::impact_metrics::IntegrityImpactType::Low => "ti-menu-deep",
        nvd_cvss::v3::impact_metrics::IntegrityImpactType::None => "ti-menu",
      },
      V3Card::A(a) => match a {
        nvd_cvss::v3::impact_metrics::AvailabilityImpactType::High => "ti-lock-access-off",
        nvd_cvss::v3::impact_metrics::AvailabilityImpactType::Low => "ti-lock-x",
        nvd_cvss::v3::impact_metrics::AvailabilityImpactType::None => "ti-lock-access",
      },
      V3Card::S(s) => match s {
        nvd_cvss::v3::scope::ScopeType::Unchanged => "ti-replace-off",
        nvd_cvss::v3::scope::ScopeType::Changed => "ti-replace",
      },
    }
  }
}
#[derive(PartialEq, Clone, Properties)]
pub struct V2CardTagProps {
  pub props: V2Card,
}
pub struct V2CardTag {
  inner: V2Card,
  i18n: MessageContext,
  _context_listener: ContextHandle<MessageContext>,
}
#[derive(Clone, PartialEq)]
pub enum V2Card {
  AV(nvd_cvss::v2::access_vector::AccessVectorType),
  AC(nvd_cvss::v2::access_complexity::AccessComplexityType),
  AU(nvd_cvss::v2::authentication::AuthenticationType),
  C(nvd_cvss::v2::impact_metrics::ConfidentialityImpactType),
  I(nvd_cvss::v2::impact_metrics::IntegrityImpactType),
  A(nvd_cvss::v2::impact_metrics::AvailabilityImpactType),
}

impl Component for V2CardTag {
  type Message = Msg;
  type Properties = V2CardTagProps;

  fn create(ctx: &Context<Self>) -> Self {
    let v2 = ctx.props().clone().props;
    let (i18n, lang) = ctx
      .link()
      .context::<MessageContext>(ctx.link().callback(Msg::Lang))
      .unwrap();
    Self {
      inner: v2,
      i18n,
      _context_listener: lang,
    }
  }
  fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
    match msg {
      Msg::Lang(i18n) => {
        self.i18n = i18n;
        true
      }
    }
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    let (name, value) = match self.inner.clone() {
      V2Card::AV(v) => ("Access Vector", format!("{:?}", v)),
      V2Card::AC(v) => ("Access Complexity", format!("{:?}", v)),
      V2Card::AU(v) => ("Authentication", format!("{:?}", v)),
      V2Card::C(v) => ("Confidentiality Impact", format!("{:?}", v)),
      V2Card::I(v) => ("Integrity Impact", format!("{:?}", v)),
      V2Card::A(v) => ("Availability Impact", format!("{:?}", v)),
    };
    let h = self.inner.help();
    let icon = self.inner.icon();
    let class_str = self.inner.color(&h.worth);
    let des = h.des;
    html! {
        <div class="justify-content-between align-items-start">
          <li class="card card-sm card-link card-link-pop">
            <div class={classes!(["card-status-start",class_str])}></div>
            <div class="card-header p-2"><h5 class="card-title">{self.i18n.t(name)}</h5>
            <div class="card-actions">
            <TooltipPopover
              toggle={"toggle"}
              placement={"top"}
              content={des}>
              <span class={classes!(["badge",class_str])}>
                <i class={classes!( ["ti",icon])}></i>{self.i18n.t(&value)}
              </span>
            </TooltipPopover>
            </div>
            </div>
          </li>
        </div>
    }
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
  fn icon(&self) -> &'static str {
    match self {
      V2Card::AV(av) => match av {
        nvd_cvss::v2::access_vector::AccessVectorType::Network => "ti-network",
        nvd_cvss::v2::access_vector::AccessVectorType::AdjacentNetwork => "ti-cloud-network",
        nvd_cvss::v2::access_vector::AccessVectorType::Local => "ti-current-location",
      },
      V2Card::AC(ac) => match ac {
        nvd_cvss::v2::access_complexity::AccessComplexityType::High => "ti-mood-unamused",
        nvd_cvss::v2::access_complexity::AccessComplexityType::Medium => "ti-mood-unamused",
        nvd_cvss::v2::access_complexity::AccessComplexityType::Low => "ti-mood-smile",
      },
      V2Card::AU(pr) => match pr {
        nvd_cvss::v2::authentication::AuthenticationType::Multiple => "ti-lock-check",
        nvd_cvss::v2::authentication::AuthenticationType::Single => "ti-lock-pause",
        nvd_cvss::v2::authentication::AuthenticationType::None => "ti-lock-open",
      },
      V2Card::C(c) => match c {
        nvd_cvss::v2::impact_metrics::ConfidentialityImpactType::Complete => "ti-eye",
        nvd_cvss::v2::impact_metrics::ConfidentialityImpactType::Partial => "ti-eye-x",
        nvd_cvss::v2::impact_metrics::ConfidentialityImpactType::None => "ti-eye-closed",
      },
      V2Card::I(i) => match i {
        nvd_cvss::v2::impact_metrics::IntegrityImpactType::Complete => "ti-menu-2",
        nvd_cvss::v2::impact_metrics::IntegrityImpactType::Partial => "ti-menu-deep",
        nvd_cvss::v2::impact_metrics::IntegrityImpactType::None => "ti-menu",
      },
      V2Card::A(a) => match a {
        nvd_cvss::v2::impact_metrics::AvailabilityImpactType::Complete => "ti-lock-access-off",
        nvd_cvss::v2::impact_metrics::AvailabilityImpactType::Partial => "ti-lock-x",
        nvd_cvss::v2::impact_metrics::AvailabilityImpactType::None => "ti-lock-access",
      },
    }
  }
}
