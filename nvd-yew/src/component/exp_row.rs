use nvd_model::exploit::Exploit;
use yew::prelude::*;

// 供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct ExpProps {
  pub props: Exploit,
}

pub struct EXPRow;

impl Component for EXPRow {
  type Message = ();
  type Properties = ExpProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let ExpProps { props, .. } = ctx.props().clone();
    let update = props.updated_at.to_string();
    let name = props.name;
    let path = props.path.clone();
    let source = props.source.clone();
    let meta = props.meta.clone();
    let is_verified = props.verified;
    let description = props.description.unwrap_or(String::from("N/A"));
    html! {
    <>
        <tr class="table-group-divider">
          <th scope="row"  rowspan="2">
              {name.clone()}
          </th>
          <td class="w-25 text-truncate text-nowrap">{self.source(&source)}</td>
          <td class="w-25 text-truncate text-nowrap">{self.verified(is_verified)}</td>
          <td class="w-25 text-truncate text-nowrap">{self.path(&source,&name,&path)}</td>
          <td class="w-25 text-truncate text-nowrap">{format!("{:?}",meta.inner)}</td>
          <td class="w-25 text-truncate text-nowrap">
            {update}
          </td>
        </tr>
        <tr class="table-success">
          <th scope="row" colspan="7" class="table table-active text-truncate" style="max-width: 150px;">{description}</th>
        </tr>
    </>
    }
  }
}

impl EXPRow {
  fn verified(&self, is_verified: u8) -> Html {
    if is_verified == 1 {
      html! {<div><span class="badge bg-green"><i class="ti ti-check"></i>{"Verified"}</span></div>}
    } else {
      html! {<div><span class="badge bg-red"><i class="ti ti-x"></i>{"Not verified"}</span></div>}
    }
  }
  fn path(&self, source: &str, name: &str, path: &str) -> Html {
    let exploit_url = match source {
      "exploit-db" => format!("https://www.exploit-db.com/exploits/{}", name),
      "nuclei-templates" => format!(
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/{}",
        path
      ),
      _ => String::new(),
    };
    html! {<div><a href={exploit_url} class="text-reset text-nowrap" target="_blank" rel="noreferrer"><i class="ti ti-external-link"></i>{path}</a></div>}
  }
  fn source(&self, source: &str) -> Html {
    match source {
      "exploit-db" => {
        html! {<div><span class="badge bg-yellow"><i class="ti ti-bug"></i>{source}</span></div>}
      }
      "nuclei-templates" => {
        html! {<div><span class="badge bg-azure"><i class="ti ti-storm"></i>{source}</span></div>}
      }
      _ => {
        html! {<div><span class="badge bg-green"><i class="ti ti-check"></i>{source}</span></div>}
      }
    }
  }
}
