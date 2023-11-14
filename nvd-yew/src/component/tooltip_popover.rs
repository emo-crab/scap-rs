use crate::console_log;
use wasm_bindgen::{prelude::Closure, JsCast, JsValue};
use web_sys::{Element, HtmlButtonElement, HtmlElement};
use yew::prelude::*;
// https://github.com/orgs/twbs/discussions/39197#discussioncomment-7034624
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call
// https://getbootstrap.com/docs/5.3/components/popovers/#methods
#[derive(PartialEq, Clone)]
pub enum TooltipPopoverType {
  Toggle,
  Popover,
}
#[derive(PartialEq, Clone)]
pub enum Placement {
  Top,
  Right,
  Bottom,
  Left,
}

impl ToString for Placement {
  fn to_string(&self) -> String {
    match self {
      Placement::Top => "top".to_string(),
      Placement::Right => "right".to_string(),
      Placement::Bottom => "bottom".to_string(),
      Placement::Left => "left".to_string(),
    }
  }
}
impl ToString for TooltipPopoverType {
  fn to_string(&self) -> String {
    match self {
      TooltipPopoverType::Toggle => "toggle".to_string(),
      TooltipPopoverType::Popover => "popover".to_string(),
    }
  }
}
#[derive(PartialEq, Clone, Properties)]
pub struct TooltipPopoverProp {
  pub toggle: TooltipPopoverType,
  pub placement: Placement,
  pub html: bool,
  pub content: String,
  pub children: Html,
}
pub struct TooltipPopover;
impl Component for TooltipPopover {
  type Message = ();
  type Properties = TooltipPopoverProp;

  fn create(ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let content = ctx.props().content.clone();
    let html = ctx.props().html;
    let placement = ctx.props().placement.to_string();
    let toggle = ctx.props().toggle.to_string();
    let children = ctx.props().children.clone();
    let on_mouse_enter = {
      let role = toggle.clone();
      Callback::from(move |event: MouseEvent| {
        event.stop_propagation();
        let target = event.target_unchecked_into::<HtmlElement>();
        let window = web_sys::window().unwrap();
        let bootstrap = js_sys::Reflect::get(&window, &wasm_bindgen::JsValue::from("bootstrap"))
          .expect("Error! Failed to get property bootstrap");
        let popover = js_sys::Reflect::get(&bootstrap, &JsValue::from("Popover"))
          .expect("Error! Failed to get property Popover");
        let get_or_create_instance =js_sys::Reflect::get(&popover, &JsValue::from("getOrCreateInstance"))
            .expect("Error! Failed to get property getOrCreateInstance");
        let popover_bootstrap = get_or_create_instance.clone().unchecked_into::<js_sys::Function>().call1(&popover,&target).expect("Error! Failed to call function getOrCreateInstance");
        console_log!("{:?}", popover_bootstrap);
        let show_popover = js_sys::Reflect::get(&popover_bootstrap, &JsValue::from("show"))
            .expect("Error! Failed to get property show");
        let callback = Closure::wrap(Box::new(move |_: MouseEvent| {
          show_popover
              .clone()
              .unchecked_into::<js_sys::Function>()
              .call0(&popover_bootstrap)
              .expect("Error! Failed to call function show");
        }) as Box<dyn FnMut(_)>);
        target
            .unchecked_into::<Element>()
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .expect("Error! Failed to add event listener");
        callback.forget();
        // // let target = target.parent_element().unwrap();
        // let document = target.owner_document().unwrap();
        // let id = format!("popover{}", chrono::Utc::now().timestamp());
        // target.set_attribute("aria-describedby", &id).unwrap();
        // let mut div = document.create_element("div").unwrap();
        // div.set_id(&id);
        // div.set_class_name("popover bs-popover-auto fade show");
        // div.set_attribute("role", role.as_str()).unwrap();
        // div
        //     .set_attribute(
        //       "style",
        //       &format!("position: fixed; top: 0; inset: 0px auto auto 0px; margin: 0px; transform: translate(0px, 0px); z-index:999;"),
        //     )
        //     .unwrap();
        // div.set_attribute("data-popper-placement", "top").unwrap();
        // let doc = div.owner_document().unwrap();
        // let mut arrow = doc.create_element("div").unwrap();
        // let mut body = doc.create_element("div").unwrap();
        // arrow.set_class_name("popover-arrow bg-info");
        // arrow
        //   .set_attribute("style", "position: fixed; top: 0;")
        //   .unwrap();
        // body.set_class_name("popover-body bg-info");
        // body.set_inner_html("Top popover");
        // div.append_child(&arrow).unwrap();
        // div.append_child(&body).unwrap();
        // target.append_child(&div).unwrap();
        // console_log!("{:?}", target.get_attribute_names());
      })
    };
    let on_mouse_leave = Callback::from(|event: MouseEvent| {
      event.stop_propagation();
      let target = event.target_unchecked_into::<HtmlButtonElement>();
      let target = target.parent_element().unwrap();
      // match target.get_attribute("aria-describedby") {
      //   None => {}
      //   Some(id) => {
      //     let el = target
      //       .owner_document()
      //       .unwrap()
      //       .query_selector(&format!("#{}", id))
      //       .unwrap();
      //     if let Some(e) = el {
      //       e.remove();
      //     }
      //   }
      // };
    });
    html! {
      <div class="justify-content-between align-items-start">
        <span
          tabindex=0
          onmouseenter={on_mouse_enter}
          onmouseleave={on_mouse_leave}
          data-bs-toggle={toggle.clone()}
          data-bs-container="body"
          data-bs-placement={placement}
          data-bs-html={html.to_string()}
          data-bs-content={content.clone()}
        >
        {children}
        </span>
      </div>
    }
  }
}
