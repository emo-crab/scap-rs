use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;

// https://github.com/yewstack/yew/tree/master/examples/contexts
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct I18n {
  pub lang: Vec<String>,
  // 原来文本：_语言：翻译
  // Home: zh: 主页
  pub translations: HashMap<String, HashMap<String, String>>,
  current_lang: String,
  pub current_translations: HashMap<String, String>,
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
    let mut translations: HashMap<String, HashMap<String, String>> = HashMap::new();
    translations.insert(
      "zh".to_string(),
      HashMap::from_iter([("Home".to_string(), "主页".to_string())]),
    );
    translations.insert(
      "en".to_string(),
      HashMap::from_iter([("Home".to_string(), "Home".to_string())]),
    );
    let current_translations = HashMap::new();
    let current_translations = translations
      .get(&current_lang)
      .unwrap_or(&current_translations)
      .clone();
    Self {
      lang: translations.keys().map(|s| s.to_string()).collect(),
      translations,
      current_lang,
      current_translations,
    }
  }
}

impl I18n {
  pub fn set_lang(&self, lang: String) -> Self {
    let lang = lang.to_lowercase();
    let mut i18n = self.clone();
    if i18n.lang.contains(&lang) {
      i18n.current_lang = lang;
      i18n.current_translations = i18n
        .translations
        .get(&i18n.current_lang)
        .unwrap_or(&HashMap::new())
        .clone();
      let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
      storage.set_item("lang", &self.current_lang).unwrap();
    }
    i18n
  }
  pub fn t(&self, text: &str) -> String {
    if let Some(translation) = self.current_translations.get(text) {
      return translation.to_string();
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
          <i class="ti ti-language"></i>{i18n.t("Home")}
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
