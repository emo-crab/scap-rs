use crate::modules::cve::Cve;
use crate::routes::Route;
use yew::prelude::*;
use yew_router::prelude::*;

pub struct CVERow;
impl Component for CVERow {
  type Message = ();
  type Properties = Cve;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, ctx: &Context<Self>) -> Html {
    let c = ctx.props().clone();
    let cve_id = c.id;
    let description = c
      .description
      .description_data
      .iter()
      .map(|d| d.value.clone())
      .collect::<Vec<String>>();
    // let cvssv2 = c.cvss2_score
    html! {
    <>
        <tr class="table-group-divider">
          <td><a href={format!("/cve/{}",cve_id)} class="text-reset" tabindex="-1" target="_blank"></a>
          <Link<Route> classes={classes!("text-reset")} to={Route::Cve{id:{cve_id.clone()}}}>
             <i class="bi bi-arrow-up-left"></i>
              {cve_id.clone()}
          </Link<Route>>
          </td>
          <td>{"Design Works"}</td>
          <td>
            <span class="flag flag-country-us"></span>
            {"Carlson Limited"}
          </td>
          <td>
            {c.cvss2_score}
          </td>
          <td>
            {c.cvss3_score}
          </td>
          <td>
            <span class="badge bg-success me-1"></span> {"Paid"}
          </td>
          <td>{"$887"}</td>
        </tr>
        <tr class="table-active">
          <td colspan="7" class="table-active text-truncate" style="max-width: 150px;">{description.join("")}</td>
        </tr>
    </>
    }
  }
}
