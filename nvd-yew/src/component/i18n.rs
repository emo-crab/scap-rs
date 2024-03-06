use std::collections::HashMap;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;

// https://github.com/yewstack/yew/tree/master/examples/contexts
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct I18n {
  // 原来文本：_语言：翻译
  // Home: zh: 主页
  pub translations: HashMap<String, HashMap<String, String>>,
  pub current_lang: String,
}

impl Reducible for I18n {
  type Action = String;
  fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
    let s = self.set_lang(action);
    s.into()
  }
}

impl Default for I18n {
  fn default() -> Self {
    let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    let default_lang = web_sys::window()
      .unwrap()
      .navigator()
      .language()
      .unwrap_or("en-US".to_string())
      .split_once('-')
      .unwrap_or(("en", "US"))
      .0
      .to_string();
    let current_lang = storage
      .get_item("lang")
      .unwrap_or_default()
      .unwrap_or(default_lang);
    let translations: HashMap<String, HashMap<String, String>> =
      serde_json::from_str(include_str!("../../i18n.json")).unwrap_or_default();
    Self {
      translations,
      current_lang,
    }
  }
}

impl I18n {
  pub fn set_lang(&self, lang: String) -> Self {
    let lang = lang.to_lowercase();
    let mut i18n = self.clone();
    let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
    storage.set_item("lang", &lang).unwrap();
    i18n.current_lang = lang;
    i18n
  }
  pub fn t(&self, text: &str) -> String {
    if let Some(translation) = self.translations.get(text) {
      return translation
        .get(&self.current_lang)
        .unwrap_or(&text.to_string())
        .to_string();
    }
    text.to_string()
  }
}

pub type MessageContext = UseReducerHandle<I18n>;

// 在app上层创建，下面组件可以获取到上下文
#[derive(Debug, Clone, PartialEq, Properties)]
pub struct I18nProviderProp {
  #[prop_or_default]
  pub children: Html,
}

#[function_component]
pub fn MessageProvider(props: &I18nProviderProp) -> Html {
  let msg = use_reducer(I18n::default);
  html! {
      <ContextProvider<MessageContext> context={msg}>
          {props.children.clone()}
      </ContextProvider<MessageContext>>
  }
}

// 选择语言组件
#[function_component]
pub fn LangSelector() -> Html {
  let i18n = use_translation();
  let on_select_change = {
    let i18n = i18n.clone();
    move |e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let lang: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      i18n.dispatch(lang)
    }
  };
  html! {
    <div class="nav-item d-none d-md-flex me-3">
        <div class="dropdown">
          <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown">
          <i class="ti ti-language"></i>{i18n.t("Lang")}
          </button>
          <div class="dropdown-menu">
          <li>
            <button onclick={on_select_change.clone()} type="button" class="dropdown-item" value="ZH">
              <span class="flag flag-sm flag-country-cn" style="pointer-events: none;"></span>{"简体中文"}
            </button>
          </li>
          <li>
            <button onclick={on_select_change.clone()} type="button" class="dropdown-item" value="EN">
              <span class="flag flag-sm flag-country-us" style="pointer-events: none;"></span>{"English"}
            </button>
          </li>
        </div>
      </div>
    </div>
  }
}

#[hook]
pub fn use_translation() -> MessageContext {
  use_context::<MessageContext>().expect("No I18n context provided")
}
