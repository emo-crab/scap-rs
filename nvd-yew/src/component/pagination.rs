use crate::component::use_translation;
use crate::modules::Paging;
use yew::prelude::*;

// 通用分页组件
#[derive(PartialEq, Clone, Properties)]
pub struct PaginationProps {
  pub paging: Paging,
  pub next_page: Callback<MouseEvent>,
  pub prev_page: Callback<MouseEvent>,
  pub to_page: Callback<MouseEvent>,
}
#[function_component]
pub fn Pagination(props: &PaginationProps) -> Html {
  let PaginationProps {
    paging,
    to_page,
    next_page,
    prev_page,
    ..
  } = props;
  let i18n = use_translation();
  let mut page_lists: Vec<(String, Vec<String>)> = Vec::new();
  let mut page_count = paging.total / 10;
  if paging.total % 10 != 0 {
    page_count += 1;
  }
  for n in 1..=page_count {
    let mut class_list = Vec::new();
    // 当前激活的页面
    let active = paging.page + 1;
    if active == n {
      class_list.push("active".to_string());
    }
    // 前三个，后三个，激活页面三个
    if n <= 2 || n > page_count - 2 || active == n {
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
        <p class="m-0 text-muted">{i18n.t("Show")} <span class="badge">{paging.page*paging.size+1}</span> {i18n.t("To")} <span class="badge">{(paging.page+1)*paging.size}</span> {i18n.t("Count")} <span>{" "}</span> {i18n.t("Entries")}<span class="badge">{paging.total}</span></p>
        <ul class="pagination m-0 ms-auto">
          <li class={classes!(["page-item",if paging.page == 0 { "disabled" } else { "" }])}>
            <button class="btn page-link" onclick={prev_page}>
              {i18n.t("Prev")}
              <i class="ti ti-chevron-left"></i>
            </button>
          </li>
          {
            page_lists.into_iter().map(move|(n,active)|{
            html!{<li class={classes!(active)}><button class="page-link" onclick={to_page.clone()} value={n.to_string()}>{n}</button></li>}
          }).collect::<Html>()
          }
          <li class={classes!(["page-item",if paging.page>=paging.total { "disabled" } else { "" }])}>
            <button class="btn page-link" onclick={next_page}>
              {i18n.t("Next")}
              <i class="ti ti-chevron-right"></i>
            </button>
          </li>
        </ul>
      </div>
  }
}
