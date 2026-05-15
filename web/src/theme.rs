
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Theme {
    #[default]
    Mist,
    Dusk,
}

impl Theme {
    pub fn attr(&self) -> &'static str {
        match self {
            Theme::Mist => "mist",
            Theme::Dusk => "dusk",
        }
    }
    pub fn toggle(self) -> Self {
        match self {
            Theme::Mist => Theme::Dusk,
            Theme::Dusk => Theme::Mist,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Theme::Mist => "Mist",
            Theme::Dusk => "Dusk",
        }
    }
}

/// Reads the persisted theme preference from localStorage.
pub fn load_theme() -> Theme {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("ensia_theme").ok().flatten())
        .map(|v| if v == "dusk" { Theme::Dusk } else { Theme::Mist })
        .unwrap_or_default()
}

/// Applies the current theme to the document root element.
pub fn apply_theme(theme: Theme) {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Some(root) = doc.document_element() {
            let _ = root.set_attribute("data-theme", theme.attr());
        }
    }
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
    {
        let _ = storage.set_item("ensia_theme", theme.attr());
    }
}
