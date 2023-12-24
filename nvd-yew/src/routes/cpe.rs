use yew::prelude::*;
use super::products::ProductInfoList;
use super::vendor::VendorInfoList;
pub struct VendorProducts;
impl Component for VendorProducts {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self {}
  }
  fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
    false
  }
  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
        <div class="card">
      <div class="row">
      <div class="col-md-6">
      <VendorInfoList/>
      </div>
      <div class="col-md-6">
      <ProductInfoList/>
      </div>
      </div>
        </div>
    }
  }
}
