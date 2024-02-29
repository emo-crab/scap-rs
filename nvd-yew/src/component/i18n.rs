use crate::console_log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use web_sys::{EventTarget, HtmlButtonElement};
use yew::prelude::*;

// https://github.com/futursolo/stylist-rs/tree/master/examples/yew-theme-context
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct I18nProvider {
  pub lang: Vec<String>,
  pub translations: HashMap<String, HashMap<String, String>>,
  current_lang: String,
  pub current_translations: HashMap<String, String>,
}

// 在app上层创建，下面组件可以获取到上下文
#[derive(Debug, Clone, PartialEq, Properties)]
pub struct I18nProviderProp {
  #[prop_or_default]
  pub lang: Vec<String>,
  #[prop_or_default]
  pub translations: HashMap<String, HashMap<String, String>>,
  pub children: Html,
}

impl Default for I18nProvider {
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

impl Component for I18nProvider {
  type Message = ();
  type Properties = I18nProviderProp;

  fn create(ctx: &Context<Self>) -> Self {
    let I18nProviderProp { translations, .. } = ctx.props().clone();
    let lang = translations
      .keys()
      .map(|k| k.to_string())
      .collect::<Vec<String>>();
    let default_i18n = I18nProvider::default();
    I18nProvider {
      lang,
      translations: translations.clone(),
      current_lang: default_i18n.current_lang.clone(),
      current_translations: translations
        .get(&default_i18n.current_lang)
        .unwrap_or(&default_i18n.current_translations)
        .clone(),
    }
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    let props = ctx.props();
    html! {
      <ContextProvider<I18nProvider> context={(*self).clone()}>
        { props.children.clone() }
      </ContextProvider<I18nProvider >>
    }
  }
}

impl I18nProvider {
  pub fn set_lang(&mut self, lang: String) {
    let lang = lang.to_lowercase();
    if self.lang.contains(&lang) {
      self.current_lang = lang;
      self.current_translations = self
        .translations
        .get(&self.current_lang)
        .unwrap_or(&HashMap::new())
        .clone();
      let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
      storage.set_item("lang", &self.current_lang).unwrap();
    }
  }
  pub fn t(&self, text: &str) -> String {
    console_log!("{:?}", self.current_translations);
    if let Some(translation) = self.current_translations.get(text) {
      return translation.to_string();
    }
    text.to_string()
  }
}

// 选择语言组件
#[derive(Debug)]
pub struct Lang {
  i18n: I18nProvider,
  _l: ContextHandle<I18nProvider>,
}

pub enum Msg {
  LangChanged(String),
  Lang(I18nProvider),
}

impl Component for Lang {
  type Message = Msg;
  type Properties = ();

  fn create(ctx: &Context<Self>) -> Self {
    let (i18n, _l) = ctx
      .link()
      .context::<I18nProvider>(ctx.link().callback(Msg::Lang))
      .unwrap();
    Self { i18n, _l }
  }
  fn update(&mut self, _ctx: &Context<Self>, msg: Msg) -> bool {
    match msg {
      Msg::LangChanged(lang) => {
        self.i18n.set_lang(lang);
      }
      Msg::Lang(i18n) => {
        console_log!("{:?}", i18n);
      }
    }
    true
  }
  fn view(&self, ctx: &Context<Self>) -> Html {
    let on_select_change = ctx.link().callback(move |e: MouseEvent| {
      let target: EventTarget = e.target().unwrap();
      let lang: String = target.clone().unchecked_into::<HtmlButtonElement>().value();
      Msg::LangChanged(lang)
    });
    html! {
      <div class="nav-item d-none d-md-flex me-3">
          <div class="dropdown">
            <button type="button" class="btn dropdown-toggle" data-bs-toggle="dropdown">
            <i class="ti ti-language"></i>{self.i18n.t("Home")}
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
}

#[hook]
pub fn use_translation() -> I18nProvider {
  use_context::<I18nProvider>().expect("No I18n context provided")
}
