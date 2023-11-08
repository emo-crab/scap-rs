
use yew::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct CVEProps {
  pub id: String,
}
pub struct CVELDetails;
impl Component for CVELDetails {
  type Message = ();
  type Properties = CVEProps;

  fn create(_ctx: &Context<Self>) -> Self {
    Self
  }

  fn view(&self, _ctx: &Context<Self>) -> Html {
    let _items = (1..=10).collect::<Vec<_>>();
    html! {
<div class="px-lg-5 px-3 py-lg-3 pt-4 bg-white">
<section class="content-header">
    <h1>{"CVE-2023-4490"}</h1>
    <ol class="breadcrumb">
        <li><a href="/">{"OpenCVE"}</a></li>
        <li><a href="/cve">{"Vulnerabilities (CVE)"}</a></li>
        <li class="active">{"CVE-2023-4490"}</li>
    </ol>
</section>
    <div class="row">
        <div class="col-sm-12 pr-0">
            <nav class="breadcrumbs">
                <ol class="breadcrumbs__list">
                    <li class="breadcrumbs__list-item-last CMSBreadCrumbsLink">
                        <a href="http://nvd.nist.gov/vuln/detail/CVE-2023-43382" target="_blank">{"NVD"}</a>
                    </li>
                    <li class="breadcrumbs__list-item-last CMSBreadCrumbsLink">
                        {"应用程序"}
                    </li>
                    <li class="breadcrumbs__list-item-last CMSBreadCrumbsLink">
                        {"CVE-2023-43382"}
                    </li>
                </ol>
            </nav>
        </div>
    </div>
    <div class="row pt-3">
        <div class="col-sm-8">
            <div>
                <h5 class="header__title">
                    <span class="header__title__text" style="vertical-align: middle;">{"dreamer_cms 安全漏洞 (CVE-2023-43382)"}</span>
                </h5>
            </div>
            <div class="d-flex flex-lg-nowrap flex-wrap justify-content-start pt-2 col-lg-9 col-sm-12 px-0">
                <div class="col-6 col-lg-3 pl-0">
                    <div class="metric">
                        <p class="metric-label"> {"CVE编号"} </p>
                        <div class="metric-value">{"CVE-2023-43382"}</div>
                    </div>
                </div>
                <div class="col-6 col-lg-3 pl-0">
                    <div class="metric">
                        <p class="metric-label"> {"利用情况"} </p>
                        <div class="metric-value">{"暂无"}
                        </div>
                    </div>
                </div>
                <div class="col-6 col-lg-3 pl-0">
                    <div class="metric">
                        <p class="metric-label"> {"补丁情况"} </p>
                        <div class="metric-value"> {"N/A"}</div>
                    </div>
                </div>
                <div class="col-6 col-lg-3 pl-0">
                    <div class="metric">
                        <p class="metric-label"> {"披露时间"} </p>
                            <div class="metric-value"> {"2023-09-26"}</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-sm-4"></div>
    </div>
</div>
    }
  }
}
