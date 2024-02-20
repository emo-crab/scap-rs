use yew::prelude::*;
use yew_router::prelude::*;

use nvd_model::knowledge_base::KnowledgeBase;

use crate::routes::Route;

// 供应商，产品回调
#[derive(PartialEq, Clone, Properties)]
pub struct KbProps {
  pub props: KnowledgeBase,
}

pub struct KBRow;

impl Component for KBRow {
  type Message = ();
  type Properties = KbProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let KbProps { props, .. } = ctx.props().clone();
    let update = props.updated_at.to_string();
    let name = props.name;
    let links = props.links.clone();
    let source = props.source.clone();
    let meta = props.meta.clone();
    let description = if props.description.is_empty() {
      String::from("N/A")
    } else {
      props.description
    };
    html! {
    <>
        <tr class="table-group-divider">
          <th scope="row" rowspan="2">
            <Link<Route> classes={classes!(["text-reset", "text-nowrap"])} to={Route::Cve{id:{name.clone()}}}>
             <i class="ti ti-external-link"></i>{name.clone()}
            </Link<Route>>
          </th>
          <td class="w-25 text-truncate text-nowrap">{self.source(&source)}</td>
          <td class="w-25 text-truncate text-nowrap">{self.links(&source,&name,&links)}</td>
          <td class="w-25 text-truncate text-nowrap">{format!("{:?}",meta)}</td>
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

impl KBRow {
  fn links(&self, source: &str, _name: &str, links: &str) -> Html {
    let kb_url = match source {
      "attackerkb" => links.to_string(),
      _ => String::new(),
    };
    html! {<div><a href={kb_url} class="text-reset text-nowrap" target="_blank" rel="noreferrer"><i class="ti ti-external-link"></i>{links}</a></div>}
  }
  fn source(&self, source: &str) -> Html {
    match source {
      "attackerkb" => {
        html! {<div><span class="badge bg-vk"><i class="ti ti-bug"></i>{source}</span></div>}
      }
      _ => {
        html! {<div><span class="badge bg-green"><i class="ti ti-check"></i>{source}</span></div>}
      }
    }
  }
}
