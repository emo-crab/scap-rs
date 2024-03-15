use crate::component::{Accordion, MessageContext, TooltipPopover};
use nvd_cves::v4::configurations::Operator;
use yew::prelude::*;

#[derive(PartialEq, Clone, Properties)]
pub struct CVEConfigurationProps {
  pub props: Vec<nvd_cves::v4::configurations::Node>,
}

pub enum Msg {
  Lang(MessageContext),
}

pub struct CVEConfiguration {
  i18n: MessageContext,
  _context_listener: ContextHandle<MessageContext>,
}

impl Component for CVEConfiguration {
  type Message = Msg;
  type Properties = CVEConfigurationProps;

  fn create(ctx: &Context<Self>) -> Self {
    let (i18n, lang) = ctx
      .link()
      .context::<MessageContext>(ctx.link().callback(Msg::Lang))
      .unwrap();
    Self {
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
  fn view(&self, ctx: &Context<Self>) -> Html {
    let configuration = ctx.props().props.clone();
    html! {
        <Accordion name={"Configurations"}>
            <div class="table-responsive">
              if !configuration.is_empty(){
              <table class="table table-vcenter card-table table-striped">
                <thead>
                  <tr>
                    <th>{self.i18n.t("Operator")}</th>
                    <th>{self.i18n.t("Match")}</th>
                  </tr>
                </thead>
                <tbody>
                {self.node(configuration)}
                </tbody>
              </table>
            }
            </div>
        </Accordion>
    }
  }
}

fn operator(o: Operator) -> &'static str {
  match o {
    Operator::And => "ti-logic-and",
    Operator::Or => "ti-logic-or",
  }
}

impl CVEConfiguration {
  fn cpe_match(&self, m: nvd_cves::v4::configurations::Match) -> Html {
    let version_range = m.get_version_range();
    let name = nvd_cpe::CPEName::from_uri(&m.cpe23_uri).unwrap();
    let vendor = name.vendor.to_string();
    let product = name.product.to_string();
    html! {
          <tr>
          <td class="col-md-2">
            <button data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-info" value={vendor.clone()} key={vendor.clone()} title={vendor.clone()}>
              <b class="text-truncate" style="max-width: 100px;" value={vendor.clone()}>{ vendor.clone() }</b>
            </button>
          </td>
          <td class="col-md-2">
            <button data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-success"  value={product.clone()} key={product.clone()} title={product.clone()}>
              <b class="text-truncate" style="max-width: 100px;" product={product.clone()} vendor={vendor.clone()}>{ product }</b>
            </button>
          </td>
          <td class="col-md-6">{m.cpe23_uri}</td>
          <td class="col-md-1">{version_range}</td>
          </tr>
    }
  }
  fn match_head(&self, show: bool) -> Html {
    if show {
      html! {
          <thead>
            <tr>
              <th>{self.i18n.t("Vendor")}</th>
              <th>{self.i18n.t("Product")}</th>
              <th>{self.i18n.t("CPE")}</th>
              <th>{self.i18n.t("Version")}</th>
            </tr>
          </thead>
      }
    } else {
      html!()
    }
  }
  fn operator_vulnerable(
    &self,
    cpe_match: Vec<nvd_cves::v4::configurations::Match>,
    operator: Operator,
  ) -> Html {
    if cpe_match.len() == 1
      && matches!(operator, nvd_cves::v4::configurations::Operator::Or)
      && !cpe_match.first().unwrap().vulnerable
    {
      return html! {
          <TooltipPopover
          class={classes!(["form-help"])}
          toggle={"popover"}
          placement={"left"}
          content={"Running On/With"}>
          <i class={classes!( ["ti","ti-stack-2"])}></i></TooltipPopover>
      };
    }
    html!()
  }
  fn node(&self, nodes: Vec<nvd_cves::v4::configurations::Node>) -> Html {
    nodes.into_iter().map(|node| {
      html! {
            <tr>
            <td class="col-md-1">
                <i class={classes!( ["ti",operator(node.operator.clone())])}></i>{format!("{:?}",node.operator)}
                {self.operator_vulnerable(node.cpe_match.clone(),node.operator.clone())}
            </td>
            <td class="col-md-11">
              {self.node(node.children)}
              {html!{
                  <table class="table table-vcenter card-table table-striped">
                  { self.match_head(!node.cpe_match.is_empty())}
                  <tbody>
                  {node.cpe_match.into_iter().map(|m|{self.cpe_match(m)}).collect::<Html>()}
                  </tbody>
                  </table>
              }}
            </td>
          </tr>
          }
    }).collect::<Html>()
  }
}
// CVE-2023-0056
