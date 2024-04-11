use web_sys::{HtmlButtonElement, HtmlInputElement};
use yew::prelude::*;

use crate::component::use_translation;
use nvd_model::knowledge_base::QueryKnowledgeBase;

// CVE表过滤和查询回调函数
#[derive(PartialEq, Clone, Properties)]
pub struct KBQueryProps {
  pub props: QueryKnowledgeBase,
  #[prop_or_default]
  pub is_verified: Option<bool>,
  pub query_source: Callback<MouseEvent>,
  pub query: Callback<QueryKnowledgeBase>,
}

#[function_component]
pub fn KBQuery(props: &KBQueryProps) -> Html {
  // let is_verified = ctx.props().is_verified.unwrap_or_default();
  let i18n = use_translation();
  let query = props.props.clone();
  let query_source = props.query_source.clone();
  let source_input = NodeRef::default();
  let name_input = NodeRef::default();
  let search_input = NodeRef::default();
  let submit_button = NodeRef::default();
  // 点击的是b标签，但是事件冒泡会将事件传到按钮
  let on_submit = {
    let source_input = source_input.clone();
    let name_input = name_input.clone();
    let query = query.clone();
    let query_callback = props.query.clone();
    Callback::from(move |event: SubmitEvent| {
      event.prevent_default();
      let source = source_input.cast::<HtmlInputElement>().unwrap().value();
      let cve = name_input
        .cast::<HtmlInputElement>()
        .unwrap()
        .value()
        .trim()
        .to_string();
      // let search = search_input.cast::<HtmlInputElement>().unwrap().value();
      query_callback.emit(QueryKnowledgeBase {
        id: None,
        cve: None,
        name: if cve.is_empty() { None } else { Some(cve) },
        description: None,
        source: if source.is_empty() {
          None
        } else {
          Some(source)
        },
        size: query.size,
        page: None,
        verified: None,
        path: None,
        types: None,
      })
    })
  };
  let clean = {
    let source_input = source_input.clone();
    let name_input = name_input.clone();
    let search_input = search_input.clone();
    let submit_button = submit_button.clone();
    Callback::from(move |event: MouseEvent| {
      let target = event
        .target_unchecked_into::<HtmlButtonElement>()
        .parent_element()
        .unwrap();
      let v = target.get_attribute("value").unwrap_or_default();
      match v.as_str() {
        "source_input" => {
          source_input
            .cast::<HtmlInputElement>()
            .unwrap()
            .set_value("");
        }
        "name_input" => {
          name_input.cast::<HtmlInputElement>().unwrap().set_value("");
        }
        "search_input" => {
          search_input
            .cast::<HtmlInputElement>()
            .unwrap()
            .set_value("");
        }
        _ => {}
      }
      submit_button.cast::<HtmlButtonElement>().unwrap().click();
    })
  };
  html! {
  <div class="card-body border-bottom py-1">
    <div class="d-flex">
      <form class="row g-1 d-flex" onsubmit={on_submit}>
        <div class="col input-icon input-group input-group-flat text-muted">
          <input type="text" class="form-control"  aria-label="name" placeholder="Name" ref={name_input} value={query.name.clone()}/>
          <button class="input-group-text" onclick={clean.clone()} value="name_input"><i class="ti ti-x link-danger"></i></button>
        </div>
        <div class="col input-group input-group-flat">
          <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
            <i class="ti ti-brand-open-source"></i>{i18n.t("Source")}
          </button>
          <ul class="dropdown-menu">
            <li><button onclick={query_source.clone()} type="button" value="none"><span class="dropdown-item btn bg-secondary btn-sm" style="pointer-events: none;"></span>{"none"}</button></li>
            <li><button onclick={query_source.clone()} type="button" value="exploit-db"><span class="dropdown-item btn bg-yellow btn-sm" style="pointer-events: none;"></span>{"exploit-db"}</button></li>
            <li><button onclick={query_source.clone()} type="button" value="attackerkb"><span class="dropdown-item btn bg-vk btn-sm" style="pointer-events: none;"></span>{"attackerkb"}</button></li>
            <li><button onclick={query_source.clone()} type="button" value="metasploit"><span class="dropdown-item btn bg-orange btn-sm" style="pointer-events: none;"></span>{"metasploit"}</button></li>
            <li><button onclick={query_source.clone()} type="button" value="nuclei-templates"><span class="dropdown-item btn bg-azure btn-sm" style="pointer-events: none;"></span>{"nuclei-templates"}</button></li>
          </ul>
        <input type="text" class="form-control" style="display: none;" readonly=true ref={source_input} value={query.source.clone()}/>
        </div>
      <div class="col-auto d-flex">
      <button class="btn" type="submit" ref={submit_button}><i class="ti ti-search"></i></button>
      </div>
      </form>
    </div>
  </div>
      }
}
