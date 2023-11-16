use wasm_bindgen::{prelude::Closure, JsCast, JsValue};
use web_sys::{Element, HtmlElement};
use yew::prelude::*;

// https://github.com/orgs/twbs/discussions/39197#discussioncomment-7034624
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call
// https://getbootstrap.com/docs/5.3/components/popovers/#methods
#[derive(PartialEq, Clone, Default, Properties)]
pub struct TooltipPopoverProp {
  #[prop_or_else(default_toggle)]
  pub toggle: AttrValue,
  #[prop_or_else(default_trigger)]
  pub trigger: AttrValue,
  #[prop_or_else(default_placement)]
  pub placement: AttrValue,
  #[prop_or(false)]
  pub html: bool,
  #[prop_or_default]
  pub content: AttrValue,
  #[prop_or_default]
  pub class: Classes,
  #[prop_or_default]
  pub children: Html,
}

fn default_toggle() -> AttrValue {
  AttrValue::from("popover")
}
fn default_trigger() -> AttrValue {
  AttrValue::from("hover")
}
fn default_placement() -> AttrValue {
  AttrValue::from("top")
}
pub struct TooltipPopover;
impl Component for TooltipPopover {
  type Message = ();
  type Properties = TooltipPopoverProp;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let TooltipPopoverProp {
      class,
      content,
      html,
      placement,
      toggle,
      children,
      trigger,
      ..
    } = ctx.props();
    let on_mouse_enter = {
      Callback::from(move |event: MouseEvent| {
        event.stop_propagation();
        let target = event.target_unchecked_into::<HtmlElement>();
        let window = web_sys::window().unwrap();
        let bootstrap = js_sys::Reflect::get(&window, &wasm_bindgen::JsValue::from("bootstrap"))
          .expect("Error! Failed to get property bootstrap");
        let popover = js_sys::Reflect::get(&bootstrap, &JsValue::from("Popover"))
          .expect("Error! Failed to get property Popover");
        let get_or_create_instance =
          js_sys::Reflect::get(&popover, &JsValue::from("getOrCreateInstance"))
            .expect("Error! Failed to get property getOrCreateInstance");
        let popover_bootstrap = get_or_create_instance
          .clone()
          .unchecked_into::<js_sys::Function>()
          .call1(&popover, &target)
          .expect("Error! Failed to call function getOrCreateInstance");
        let show_popover = js_sys::Reflect::get(&popover_bootstrap, &JsValue::from("show"))
          .expect("Error! Failed to get property show");
        let show_callback = Closure::wrap(Box::new(move |_: MouseEvent| {
          show_popover
            .clone()
            .unchecked_into::<js_sys::Function>()
            .call0(&popover_bootstrap)
            .expect("Error! Failed to call function show");
        }) as Box<dyn FnMut(_)>);
        target
          .clone()
          .unchecked_into::<Element>()
          .add_event_listener_with_callback("click", show_callback.as_ref().unchecked_ref())
          .expect("Error! Failed to add event listener");
        show_callback.forget();
      })
    };
    html! {
      <div class={class.clone()}>
        <span
          tabindex=0
          data-bs-trigger={trigger}
          onmouseenter={on_mouse_enter}
          data-bs-toggle={toggle.clone()}
          data-bs-container="body"
          data-bs-placement={placement}
          data-bs-html={html.to_string()}
          data-bs-content={content.clone()}
        >
        {children.clone()}
        </span>
      </div>
    }
  }
}
