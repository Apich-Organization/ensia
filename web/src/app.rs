use crate::{
    components::{footer::Footer, nav::Nav},
    pages::{algorithms::AlgorithmsPage, config::ConfigPage, home::HomePage},
    theme,
};
use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Page {
    #[default]
    Home,
    Algorithms,
    Config,
}

fn page_from_hash() -> Page {
    web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| {
            let s = h.trim_start_matches('#').trim_start_matches('/');
            match s {
                s if s.starts_with("algorithms") => Page::Algorithms,
                s if s.starts_with("config") => Page::Config,
                _ => Page::Home,
            }
        })
        .unwrap_or_default()
}

pub fn navigate(page: Page) {
    let hash = match page {
        Page::Home => "#/",
        Page::Algorithms => "#/algorithms",
        Page::Config => "#/config",
    };
    if let Some(w) = web_sys::window() {
        let _ = w.location().set_hash(hash);
    }
}

#[component]
pub fn App() -> impl IntoView {
    let theme = RwSignal::new(theme::load_theme());
    let page = RwSignal::new(page_from_hash());

    provide_context(theme);
    provide_context(page);

    // Apply theme attribute on the html element whenever it changes.
    Effect::new(move |_| {
        theme::apply_theme(theme.get());
    });

    // Push hash URL whenever page changes.
    Effect::new(move |_| {
        navigate(page.get());
    });

    // Re-render KaTeX after every navigation.
    Effect::new(move |_| {
        let _ = page.get();
        let _ = js_sys::eval("window.triggerKatex && window.triggerKatex()");
    });

    view! {
        <Nav />
        <main>
            {move || match page.get() {
                Page::Home       => view! { <HomePage       /> }.into_any(),
                Page::Algorithms => view! { <AlgorithmsPage /> }.into_any(),
                Page::Config     => view! { <ConfigPage     /> }.into_any(),
            }}
        </main>
        <Footer />
    }
}
