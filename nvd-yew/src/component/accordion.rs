use yew::prelude::*;

#[derive(PartialEq, Clone, Default, Properties)]
pub struct AccordionProp {
  #[prop_or_default]
  pub name: AttrValue,
  #[prop_or_default]
  pub children: Html,
}
pub struct Accordion;

impl Component for Accordion {
  type Message = ();
  type Properties = AccordionProp;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let AccordionProp { name, children, .. } = ctx.props();
    html! {
      <div>
      <div class="accordion" id={format!("accordion-{}",name.clone())} role="tablist" aria-multiselectable="true">
        <div class="accordion-item">
          <h2 class="accordion-header" role="tab">
            <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target={format!("#collapse-{}",name.clone())} aria-expanded="true">
              {name.clone()}
            </button>
          </h2>
          <div id={format!("accordion-{}",name)} class="accordion-collapse collapse show" data-bs-parent={format!("#collapse-{}",name.clone())} style="">
            <div class="accordion-body pt-0">
            {children.clone()}
            </div>
          </div>
        </div>
      </div>
      </div>
    }
  }
}
