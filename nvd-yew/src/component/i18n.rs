use std::collections::HashMap;
use yew::{Html, Properties};

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

impl I18n {
  pub fn new(config: I18nTranslation) -> Self {
    let current_lang = config.lang.get(0).unwrap_or(&"en".to_string()).to_string();
    Self { config, current_lang }
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