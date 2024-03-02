use crate::component::use_translation;
use yew::prelude::*;

#[derive(PartialEq, Clone, Default, Properties)]
pub struct AccordionProp {
  #[prop_or_default]
  pub name: AttrValue,
  #[prop_or_default]
  pub children: Html,
}

#[function_component]
pub fn Accordion(props: &AccordionProp) -> Html {
  let i18n = use_translation();
  let AccordionProp { name, children, .. } = props;
  html! {
    <div class="accordion" id={format!("accordion-{}",name.to_lowercase())} role="tablist" aria-multiselectable="true">
      <div class="accordion-item">
        <h2 id={format!("heading-{}",name.to_lowercase())} class="accordion-header" role="tab">
          <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target={format!("#collapse-{}",name.to_lowercase())} aria-expanded="true">
            {i18n.t(name)}
          </button>
        </h2>
        <div id={format!("collapse-{}",name.to_lowercase())} class="accordion-collapse collapse show" data-bs-parent={format!("#accordion-{}",name.to_lowercase())} style="">
          <div class="accordion-body pt-0">
          {children.clone()}
          </div>
        </div>
      </div>
    </div>
  }
}
