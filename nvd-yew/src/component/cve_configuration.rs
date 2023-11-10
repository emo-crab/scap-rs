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
      <div class="accordion" id="accordion-example" role="tablist" aria-multiselectable="true">
        <div class="accordion-item">
          <h2 class="accordion-header" role="tab">
            <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-1" aria-expanded="true">
              {"Configurations"}
            </button>
          </h2>
          <div id="collapse-1" class="accordion-collapse collapse show" data-bs-parent="#accordion-example" style="">
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
                {configuration.nodes.into_iter().map(|node|{
                  html!{
                    <tr>
                    <td class="col-md-1"><i class={classes!( ["ti",operator(node.operator.clone())])}></i>{format!("{:?}",node.operator)}</td>
                    <td class="col-md-11">
                      {
                        node.children.into_iter().map(|node|{
                        {node.cpe_match.into_iter().map(|m|{
                          html!{
                          <table class="table table-vcenter card-table table-striped">
                            <thead>
                              <tr>
                                <th>{"Vulnerable"}</th>
                                <th>{"Vendor"}</th>
                                <th>{"Product"}</th>
                                <th>{"CPE"}</th>
                                <th>{"Version"}</th>
                              </tr>
                            </thead>
                            <tbody>
                              <tr>
                              <td class="col-md-1">{m.vulnerable.to_string()}</td>
                              <td class="col-md-2">{m.cpe_uri.cpe23_uri.vendor.to_string()}</td>
                              <td class="col-md-2">{m.cpe_uri.cpe23_uri.product.to_string()}</td>
                              <td class="col-md-6">{m.cpe_uri.cpe23_uri.to_string()}</td>
                              <td class="col-md-1">{m.cpe_uri.cpe23_uri.version.to_string()}</td>
                              </tr>
                            </tbody>
                          </table>
                        }
                        }).collect::<Html>()}
                      }).collect::<Html>()
                      }
                      {node.cpe_match.into_iter().map(|m|{
                          html!{
                          <table class="table table-vcenter card-table table-striped">
                            <tbody>
                              <tr>
                              <td class="col-md-1">{m.vulnerable.to_string()}</td>
                              <td class="col-md-2">{m.cpe_uri.cpe23_uri.vendor.to_string()}</td>
                              <td class="col-md-2">{m.cpe_uri.cpe23_uri.product.to_string()}</td>
                              <td class="col-md-6">{m.cpe_uri.cpe23_uri.to_string()}</td>
                              <td class="col-md-1">{m.cpe_uri.cpe23_uri.version.to_string()}</td>
                              </tr>
                            </tbody>
                          </table>
                        }
                        }).collect::<Html>()}
                    </td>
                  </tr>
                  }
                }).collect::<Html>()}
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
// CVE-2023-0056