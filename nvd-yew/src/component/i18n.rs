use crate::console_log;
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement, HtmlInputElement};
use yew::prelude::*;

// https://github.com/futursolo/stylist-rs/tree/master/examples/yew-theme-context
#[derive(Debug, Clone, PartialEq)]
struct I18nTranslation {
  pub lang: Vec<String>,
  pub translations: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Properties)]
pub struct I18nTranslationProp {
  #[prop_or_else(|| vec ! ["en".to_string(), "zh".to_string()])]
  pub lang: Vec<String>,
  pub translations: HashMap<String, HashMap<String, String>>,
  pub children: Html,
}

#[derive(Clone, PartialEq)]
pub struct I18n {
  pub config: I18nTranslation,
  current_lang: String,
}

impl Component for I18n {
  type Message = ();
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    let default_lang = web_sys::window()
      .unwrap()
      .navigator()
      .language()
      .unwrap_or("en-US".to_string())
      .split_once("-")
      .unwrap_or(("en", "US"))
      .0
      .to_string();
    let lang = storage
      .get_item("lang")
      .unwrap_or_default()
      .unwrap_or(default_lang);
    Self {
      config: I18nTranslation {
        lang: vec![],
        translations: Default::default(),
      },
      current_lang: lang,
    }
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let language_ref = NodeRef::default();
    let on_select_change = ctx.link().callback(|e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let lang: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      console_log!("{:?}",lang);
    });
    html! {
      <div class="nav-item d-none d-md-flex me-3">
        <div class="dropdown">
          <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown">
          <i class="ti ti-language" style="color: blue;"></i>{self.current_lang.to_uppercase()}</button>
          <div class="dropdown-menu">
          <li>
            <button onclick={on_select_change.clone()} type="button" class="dropdown-item" value="ZH">
              {"ZH"}<span class="flag flag-country-cn" style="pointer-events: none;"></span>
            </button>
          </li>
          <li>
            <button onclick={on_select_change.clone()} type="button" class="dropdown-item" value="EN">
              {"EN"}<span class="flag flag-country-us" style="pointer-events: none;"></span>
            </button>
          </li>
          </div>
        </div>
      </div>
    }
  }
}

impl I18n {
  pub fn new(config: I18nTranslation) -> Self {
    let current_lang = config.lang.get(0).unwrap_or(&"en".to_string()).to_string();
    Self {
      config,
      current_lang,
    }
  }
  pub fn set_lang(&mut self, lang: String) {
    if self.config.lang.contains(&lang) {
      self.current_lang = lang;
    }
  }
  pub fn t(&self, text: &str) -> String {
    if let Some(dict) = self.config.translations.get(&self.current_lang) {
      return dict.get(text).unwrap_or(&text.to_string()).to_string();
    }
    return text.to_string();
  }
}

// examples/contexts/src/msg_ctx.rs
#[function_component(I18nProvider)]
pub fn i18n_provider(props: &I18nTranslationProp) -> Html {
  let i18n = I18n::new(I18nTranslation {
    lang: props.lang.clone(),
    translations: props.translations.clone(),
  });
  let ctx = use_state(|| i18n);
  html! {<ContextProvider<I18n> context={(*ctx).clone()}>{ props.children.clone() }</ContextProvider<I18n>>}
}

#[hook]
pub fn use_translation() -> I18n {
  use_context::<I18n>().expect("No I18n context provided")
}
