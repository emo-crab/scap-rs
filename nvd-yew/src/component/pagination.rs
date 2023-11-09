use yew::prelude::*;
// 通用分页组件
#[derive(PartialEq, Clone, Properties)]
pub struct PaginationProps {
  pub limit: i64,
  pub total: i64,
  pub offset: i64,
  pub next_page: Callback<MouseEvent>,
  pub prev_page: Callback<MouseEvent>,
  pub to_page: Callback<MouseEvent>,
}
pub struct Pagination;
impl Component for Pagination {
  type Message = ();
  type Properties = PaginationProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let total = ctx.props().total;
    let limit = ctx.props().limit;
    let offset = ctx.props().offset;
    let to_page = ctx.props().to_page.clone();
    let next_page = ctx.props().next_page.clone();
    let prev_page = ctx.props().prev_page.clone();
    let mut page_lists: Vec<(String, Vec<String>)> = Vec::new();
    let mut page_count = total / 10;
    if total % 10 != 0 {
      page_count = page_count + 1;
    }
    for n in (1..=page_count).into_iter() {
      let mut class_list = Vec::new();
      // 当前激活的页面
      let active = offset / 10 + 1;
      if active == n {
        class_list.push("active".to_string());
      }
      // 前三个，后三个，激活页面三个
      if n <= 2 || n > page_count - 2 {
        page_lists.push((n.to_string(), class_list));
      } else if active == n {
        page_lists.push((n.to_string(), class_list));
      } else if n == active + 1 {
        page_lists.push((n.to_string(), class_list));
        if n < page_count - 2 {
          page_lists.push(("...".to_string(), vec!["disabled".to_string()]));
        }
      } else if n == active - 1 {
        // 离前三个很远
        if n > 3 {
          page_lists.push(("...".to_string(), vec!["disabled".to_string()]));
        }
        page_lists.push((n.to_string(), class_list));
      }
    }
    if !page_lists.contains(&("...".to_string(), vec!["disabled".to_string()])) && page_count > 6 {
      page_lists.insert(2, ("...".to_string(), vec!["disabled".to_string()]));
    }
    html! {
        <div class="card-footer card-footer-sm d-flex align-items-center">
          <p class="m-0 text-muted">{"展示"} <span>{offset+1}</span> {"到"} <span>{offset+limit}</span> {"条"} <span>{"总数"}</span>{total} </p>
          <ul class="pagination m-0 ms-auto">
            <li class={classes!(["page-item",if offset == 0 { "disabled" } else { "" }])}>
              <button class="btn page-link" onclick={prev_page}>
                {"prev"}
                <i class="ti ti-chevron-left"></i>
              </button>
            </li>
            {
              page_lists.into_iter().map(move|(n,active)|{
              html!{<li class={classes!(active)}><button class="page-link" onclick={to_page.clone()} value={n.to_string()}>{n}</button></li>}
            }).collect::<Html>()
            }
            <li class={classes!(["page-item",if offset+10>=total { "disabled" } else { "" }])}>
              <button class="btn page-link" onclick={next_page}>
                {"next"}
                <i class="ti ti-chevron-right"></i>
              </button>
            </li>
          </ul>
        </div>
    }
  }
}
