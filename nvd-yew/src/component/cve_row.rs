use yew::prelude::*;

pub struct CVERow;
impl Component for CVERow {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
    <>
        <tr>
          <td><a href="/cve/CVE-2023-5077" class="text-reset" tabindex="-1" target="_blank">{"CVE-2023-5077"}</a></td>
          <td>{"Design Works"}</td>
          <td>
            <span class="flag flag-country-us"></span>
            {"Carlson Limited"}
          </td>
          <td>
            {"87956621"}
          </td>
          <td>
            {"15 Dec 2017"}
          </td>
          <td>
            <span class="badge bg-success me-1"></span> {"Paid"}
          </td>
          <td>{"$887"}</td>
          <td class="text-end">
            <span class="dropdown">
              <button class="btn dropdown-toggle align-text-top" data-bs-boundary="viewport" data-bs-toggle="dropdown">{"Actions"}</button>
              <div class="dropdown-menu dropdown-menu-end">
                <a class="dropdown-item" href="#">
                  {"Action"}
                </a>
                <a class="dropdown-item" href="#">
                  {"Another action"}
                </a>
              </div>
            </span>
          </td>
        </tr>
    </>
    }
  }
}
