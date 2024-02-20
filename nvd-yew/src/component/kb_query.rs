use web_sys::{HtmlButtonElement, HtmlInputElement};
use yew::prelude::*;

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

pub struct KBQuery;

impl Component for KBQuery {
  type Message = ();
  type Properties = KBQueryProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    // let is_verified = ctx.props().is_verified.unwrap_or_default();
    let query = ctx.props().props.clone();
    let query_source = ctx.props().query_source.clone();
    let source_input = NodeRef::default();
    let name_input = NodeRef::default();
    let search_input = NodeRef::default();
    let submit_button = NodeRef::default();
    // 点击的是b标签，但是事件冒泡会将事件传到按钮
    let on_submit = {
      let source_input = source_input.clone();
      let name_input = name_input.clone();
      let query = query.clone();
      let query_callback = ctx.props().query.clone();
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
          page: query.page,
          links: None,
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
              {"Source"}
            </button>
            <ul class="dropdown-menu">
              <li><button onclick={query_source.clone()} type="button" class="dropdown-item btn bg-secondary btn-sm"  value="none">{"none"}</button></li>
              <li><button onclick={query_source.clone()} type="button" class="dropdown-item btn bg-blue btn-sm" value="attackerkb">{"metasploit"}</button></li>
            </ul>
          <input type="text" class="form-control" readonly=true ref={source_input} value={query.source.clone()}/>
          <button class="input-group-text" onclick={clean.clone()} value="source_input"><i class="ti ti-x link-danger"></i></button>
          </div>
        <div class="col-auto d-flex">
        <button class="btn" type="submit" ref={submit_button}><i class="ti ti-search"></i></button>
        </div>
        </form>
      </div>
    </div>
        }
  }
}
