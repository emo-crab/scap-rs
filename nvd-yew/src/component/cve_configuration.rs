use cve::configurations::Operator;
use yew::prelude::*;
#[derive(PartialEq, Clone, Properties)]
pub struct CVEConfigurationProps {
  pub props: cve::configurations::Configurations,
}
pub struct CVEConfiguration;
impl Component for CVEConfiguration {
  type Message = ();
  type Properties = CVEConfigurationProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let configuration = ctx.props().props.clone();
    html! {
      <div class="accordion" id="accordion-configurations" role="tablist" aria-multiselectable="true">
        <div class="accordion-item">
          <h2 class="accordion-header" role="tab">
            <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-configurations" aria-expanded="true">
              {"Configurations"}
            </button>
          </h2>
          <div id="collapse-configurations" class="accordion-collapse collapse show" data-bs-parent="#accordion-configurations" style="">
            <div class="accordion-body pt-0">
            <div class="table-responsive">
              <table class="table table-vcenter card-table table-striped">
                <thead>
                  <tr>
                    <th>{"Operator"}</th>
                    <th>{"Match"}</th>
                  </tr>
                </thead>
                <tbody>
                {self.node(configuration.nodes)}
                </tbody>
              </table>
            </div>
            </div>
          </div>
        </div>
      </div>
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
  fn cpe_match(&self, m: cve::configurations::Match) -> Html {
      let vendor = m.cpe_uri.cpe23_uri.vendor.to_string();
      let product = m.cpe_uri.cpe23_uri.product.to_string();
    html! {
          <tr>
          <td class="col-md-1">{m.vulnerable.to_string()}</td>
          <td class="col-md-2">
            <button data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-info" value={vendor.clone()} key={vendor.clone()} title={vendor.clone()}>
              <b class="text-truncate" style="max-width: 50px;" value={vendor.clone()}>{ vendor.clone() }</b>
            </button>
          </td>
          <td class="col-md-2">
            <button data-bs-toggle="tooltip" data-bs-placement="top" type="button" class="btn btn-sm btn-outline-success"  value={product.clone()} key={product.clone()} title={product.clone()}>
              <b class="text-truncate" style="max-width: 50px;" product={product.clone()} vendor={vendor.clone()}>{ product }</b>
            </button>
          </td>
          <td class="col-md-6">{m.cpe_uri.cpe23_uri.to_string()}</td>
          <td class="col-md-1">{m.cpe_uri.cpe23_uri.version.to_string()}</td>
          </tr>
    }
  }
  fn match_head(&self, show: bool) -> Html {
    if show {
      html! {
          <thead>
            <tr>
              <th>{"Vulnerable"}</th>
              <th>{"Vendor"}</th>
              <th>{"Product"}</th>
              <th>{"CPE"}</th>
              <th>{"Version"}</th>
            </tr>
          </thead>
      }
    } else {
      html!()
    }
  }
  fn node(&self, nodes: Vec<cve::configurations::Node>) -> Html {
    nodes.into_iter().map(|node|{
      html!{
            <tr>
            <td class="col-md-1"><i class={classes!( ["ti",operator(node.operator.clone())])}></i>{format!("{:?}",node.operator)}</td>
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
