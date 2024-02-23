use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsCast;

#[wasm_bindgen(start)]
pub fn run() {
  let window = web_sys::window().unwrap();
  let document = window.document().unwrap();
  let html_document = document.dyn_into::<web_sys::HtmlDocument>().unwrap();
  html_document.set_design_mode("on");
  let find = js_sys::Reflect::get(&window, &wasm_bindgen::JsValue::from("find")).unwrap();
  web_sys::console::log_1(&format!("{:?}", find).into());
}

#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
  a + b
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {}
}
