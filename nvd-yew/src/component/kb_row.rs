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
    let path = props.path.clone();
    let source = props.source.clone();
    let meta = props.meta.clone();
    let is_verified = props.verified;
    let description = if props.description.is_empty() {
      String::from("N/A")
    } else {
      props.description
    };
    let disabled_open = !name.starts_with("CVE-");
    let mut tags = meta
      .get_hashset("tags")
      .unwrap_or_default()
      .into_iter()
      .collect::<Vec<String>>();
    tags.sort();
    html! {
    <>
        <tr class="table-group-divider">
          <th scope="row" rowspan="2">
          {if !disabled_open{
            html!{
            <Link<Route> disabled={disabled_open} classes={classes!(["text-reset", "text-nowrap"])} to={Route::Cve{id:{name.clone()}}}>
             <i class="ti ti-external-link"></i>{name.clone()}
            </Link<Route>>
            }
          }else{
            html!{<span classes={classes!(["text-reset", "text-nowrap"])}>{name.clone()}</span>}
          }}
          </th>
          <td class="w-25 text-truncate text-nowrap">{self.source(&source)}</td>
          <td class="w-25 text-truncate text-nowrap">{self.verified(is_verified)}</td>
          <td class="w-25 text-truncate text-nowrap">{self.path(&source,&name,&path)}</td>
                    <td class="w-25 text-truncate text-nowrap">
          {html!(<span class="badge rounded-pill bg-secondary">{tags.len()}</span>)}
          {
            if !tags.is_empty(){
              tags.clone().into_iter().enumerate().filter(|(index,_)|index.lt(&3)).map(|(_,value)| {
                if value.starts_with("CVE-"){
                html!{
                <a href={format!("/cve/{}",value)} class="text-reset text-nowrap" target="_blank" rel="noreferrer"><i class="ti ti-external-link"></i>{value}</a>
                }
              }else{
                html!{<span class="text-truncate badge">{value}</span>}
              }
              }).collect::<Html>()
            }else{
            html!{
                <span class="text-truncate badge">{ "N/A" }</span>
              }
            }
          }
          {if tags.len()>3{html!(<i>{format!("{} and more",tags.len()-2)}</i>)}else{html!()}}
          </td>
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
  fn verified(&self, is_verified: u8) -> Html {
    if is_verified == 1 {
      html! {<div><span class="badge bg-green"><i class="ti ti-check"></i>{"Verified"}</span></div>}
    } else {
      html! {<div><span class="badge bg-red"><i class="ti ti-x"></i>{"Not verified"}</span></div>}
    }
  }
  fn path(&self, source: &str, name: &str, path: &str) -> Html {
    let kb_url = match source {
      "exploit-db" => format!("https://www.exploit-db.com/exploits/{}", name),
      "nuclei-templates" => format!(
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/{}",
        path
      ),
      _ => path.to_string(),
    };
    html! {<div><a href={kb_url} class="text-reset text-nowrap" target="_blank" rel="noreferrer"><i class="ti ti-external-link"></i>{path}</a></div>}
  }
  fn source(&self, source: &str) -> Html {
    match source {
      "exploit-db" => {
        html! {<div><span class="badge bg-yellow"><i class="ti ti-bug"></i>{source}</span></div>}
      }
      "nuclei-templates" => {
        html! {<div><span class="badge bg-azure"><i class="ti ti-storm"></i>{source}</span></div>}
      }
      "attackerkb" => {
        html! {<div><span class="badge bg-vk"><i class="ti ti-check"></i>{source}</span></div>}
      }
      _ => {
        html! {<div><span class="badge bg-google"><i class="ti ti-check"></i>{source}</span></div>}
      }
    }
  }
}
