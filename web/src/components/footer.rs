use crate::app::Page;
use leptos::prelude::*;

#[component]
pub fn Footer() -> impl IntoView {
    let page = expect_context::<RwSignal<Page>>();
    let go_sponsor = move |_| page.set(Page::Sponsor);

    view! {
        <footer class="footer page-wrap">
            <span>
                "\u{00A9} 2026 Xinyu Yang & Ensia Contributors \u{00B7} "
                <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener">
                    "AGPL-3.0"
                </a>
            </span>
            <div class="footer-links">
                <button class="btn-link" on:click=go_sponsor>
                    "Sponsor"
                </button>
                <a href="https://github.com/Apich-Organization/ensia" target="_blank" rel="noopener">
                    "Source"
                </a>
                <a href="https://github.com/Apich-Organization/ensia/issues" target="_blank" rel="noopener">
                    "Issues"
                </a>
                <a href="https://github.com/Apich-Organization/ensia/blob/main/SECURITY.md"
                   target="_blank" rel="noopener">
                    "Security"
                </a>
                <a href="https://discord.gg/D5e2czMTT9" target="_blank" rel="noopener">
                    "Discord"
                </a>
            </div>
        </footer>
    }
}
