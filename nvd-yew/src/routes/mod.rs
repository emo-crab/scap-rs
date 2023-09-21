mod home;
mod page_not_found;

use yew::prelude::*;
use yew_router::prelude::*;
use home::Home;
use page_not_found::PageNotFound;
#[derive(Routable, PartialEq, Eq, Clone, Debug)]
pub enum Route {
    #[at("/cve/:id")]
    Cve { id: String },
    #[at("/cve")]
    CveList,
    #[at("/")]
    Home,
    #[not_found]
    #[at("/404")]
    NotFound,
}
pub fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => {
            html! { <Home /> }
        }
        Route::NotFound => {
            html! { <PageNotFound /> }
        }
        _ => {
            html! { <PageNotFound /> }
        }
    }
}