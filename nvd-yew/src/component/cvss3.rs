use crate::routes::Route;
use yew::prelude::*;
use yew_router::prelude::*;
pub struct CVSS3;
impl Component for CVSS3 {
  type Message = ();
  type Properties = ();

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    html! {
        <>
        <div class="row">
          <div class="col-md-4">
            <div class="card border-danger mb-3">
              <div class="card-body">
                <h3>{"9.8"}<sup style="font-size: 20px"> {"/10"}</sup></h3>
                <p class="card-text">{"CVSS v3.0 : CRITICAL"}</p>
              </div>
              <div class="card-footer text-bg-light text-center text-muted">
                <a href="https://www.first.org/cvss/specification-document" target="_blank">
                    {"V3 Legend"} <i class="bi bi-arrow-up-right-square"></i></a>
              </div>
            </div>
            <p><strong>{"Vector :"}</strong> {"AV:N/AC:L/Au:N/C:P/I:N/A:N"}</p>
            <p><strong>{"Exploitability :"}</strong> {"3.9 /"} <strong>{"Impact:"}</strong> {"3.6"}</p>
          </div>
          <div class="col-md-4">
            <div class="grid gap-3">
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
          </div>
          </div>
          <div class="col-md-4">
            <div class="grid gap-3">
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
            <li class="p-3 list-group-item d-flex justify-content-between align-items-start list-group-item-danger">
              {"Attack Vector"}
              <span class="badge text-bg-danger">{"NETWORK"}</span>
            </li>
          </div>
          </div>
    </div>
    // <div class="row">
    //     <div class="col-md-4">
    //         <div class="small-box bg-critical">
    //             <div class="inner">
    //                 <h3>{"9.8"}<sup style="font-size: 20px">{" /10"}</sup></h3>
    //                 <p>{"CVSS v3.0 : CRITICAL"}</p>
    //             </div>
    //             <div class="icon">
    //                 <i class="ion ion-stats-bars"></i>
    //             </div>
    //             <a href="https://www.first.org/cvss/specification-document" target="_blank" class="small-box-footer">
    //                 {"V3 Legend "}<i class="fa fa-arrow-circle-right"></i>
    //             </a>
    //         </div>
    //         <p><strong>{"Vector :"}</strong> </p>
    //         <p><strong>{"Exploitability :"}</strong> {"3.9 / "}<strong>{"Impact:"}</strong> {"5.9"}</p>
    //     </div>
    //
    //     <div class="col-md-4">
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Attack Vector"}
    //                         <span class="pull-right label label-danger">{"NETWORK"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Attack Complexity"}
    //                         <span class="pull-right label label-danger">{"LOW"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Privileges Required"}
    //                         <span class="pull-right label label-danger">{"NONE"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"User Interaction"}
    //                         <span class="pull-right label label-danger">{"NONE"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //     </div>
    //     <div class="col-md-4">
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Confidentiality Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Integrity Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Availability Impact"}
    //                         <span class="pull-right label label-danger">{"HIGH"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //         <div class="panel-group panel-group-cvss">
    //             <div class="panel panel-default">
    //                 <div class="panel-heading">
    //                     <h4 class="panel-title">
    //                         {"Scope"}
    //                         <span class="pull-right label label-default">{"UNCHANGED"}</span>
    //                     </h4>
    //                 </div>
    //             </div>
    //         </div>
    //     </div>
    // </div>
        </>
        }
  }
}
