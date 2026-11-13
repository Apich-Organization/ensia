use crate::{
    components::{footer::Footer, nav::Nav},
    pages::{
        algorithms::AlgorithmsPage, benchmark::BenchmarkPage, config::ConfigPage, home::HomePage,
        sponsor::SponsorPage,
    },
    theme,
};
use leptos::prelude::*;
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Page {
    #[default]
    Home,
    Algorithms,
    Benchmark,
    Config,
    Sponsor,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = window, catch)]
    fn renderMathInElement(
        elem: &web_sys::HtmlElement,
        options: &js_sys::Object,
    ) -> Result<(), JsValue>;
}

use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;

pub fn trigger_katex() -> Result<(), JsValue> {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return Ok(()),
    };

    let is_katex_ready = js_sys::Reflect::has(&window, &"renderMathInElement".into()).unwrap_or(false);

    if !is_katex_ready {
        // KaTeX is not loaded yet, set up a retry loop
        spawn_local(async move {
            for _ in 0..10 { // Retry for a short duration
                TimeoutFuture::new(100).await;
                if let Some(w) = web_sys::window() {
                    if js_sys::Reflect::has(&w, &"renderMathInElement".into()).unwrap_or(false) {
                        let _ = trigger_katex_inner();
                        break;
                    }
                }
            }
        });
        return Ok(());
    }
    trigger_katex_inner()
}

fn trigger_katex_inner() -> Result<(), JsValue> {
    if let Some(window) = web_sys::window() {
        if let Some(document) = window.document() {
            if let Some(body) = document.body() {
                let options = js_sys::Object::new();

                let delimiters = js_sys::Array::new();

                let delim1 = js_sys::Object::new();
                js_sys::Reflect::set(&delim1, &"left".into(), &"$$".into())?;
                js_sys::Reflect::set(&delim1, &"right".into(), &"$$".into())?;
                js_sys::Reflect::set(&delim1, &"display".into(), &true.into())?;
                delimiters.push(&delim1);

                let delim2 = js_sys::Object::new();
                js_sys::Reflect::set(&delim2, &"left".into(), &"$".into())?;
                js_sys::Reflect::set(&delim2, &"right".into(), &"$".into())?;
                js_sys::Reflect::set(&delim2, &"display".into(), &false.into())?;
                delimiters.push(&delim2);

                js_sys::Reflect::set(&options, &"delimiters".into(), &delimiters)?;
                js_sys::Reflect::set(&options, &"throwOnError".into(), &false.into())?;

                let _ = renderMathInElement(&body, &options);
            }
        }
    }
    Ok(())
}

fn page_from_hash() -> Page {
    web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| {
            let s = h.trim_start_matches('#').trim_start_matches('/');
            match s {
                s if s.starts_with("algorithms") => Page::Algorithms,
                s if s.starts_with("benchmark") => Page::Benchmark,
                s if s.starts_with("config") => Page::Config,
                s if s.starts_with("sponsor") => Page::Sponsor,
                _ => Page::Home,
            }
        })
        .unwrap_or_default()
}

pub fn navigate(page: Page) {
    let hash = match page {
        Page::Home => "#/",
        Page::Algorithms => "#/algorithms",
        Page::Benchmark => "#/benchmark",
        Page::Config => "#/config",
        Page::Sponsor => "#/sponsor",
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
        let _ = trigger_katex();
    });

    view! {
        <Nav />
        <main>
            {move || match page.get() {
                Page::Home       => view! { <HomePage       /> }.into_any(),
                Page::Algorithms => view! { <AlgorithmsPage /> }.into_any(),
                Page::Benchmark  => view! { <BenchmarkPage  /> }.into_any(),
                Page::Config     => view! { <ConfigPage     /> }.into_any(),
                Page::Sponsor    => view! { <SponsorPage    /> }.into_any(),
            }}
        </main>
        <Footer />
    }
}
