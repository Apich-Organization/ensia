use crate::models::config::*;
use leptos::{html, prelude::*};
use wasm_bindgen_futures::spawn_local;
use gloo_timers::future::TimeoutFuture;

// ── Helpers ────────────────────────────────────────────────────────────────

const STORAGE_KEY: &str = "ensia_config_v1";

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn highlight_toml_value(val: &str) -> String {
    let t = val.trim();
    if t.starts_with('"') || t.starts_with('\'') {
        format!("<span class='th-str'>{}</span>", escape_html(t))
    } else if t == "true" || t == "false" {
        format!("<span class='th-bool'>{}</span>", t)
    } else if t.starts_with('[') {
        format!("<span class='th-arr'>{}</span>", escape_html(t))
    } else {
        format!("<span class='th-num'>{}</span>", escape_html(t))
    }
}

pub fn highlight_toml(toml: &str) -> String {
    let mut out = String::with_capacity(toml.len() * 2);
    for line in toml.lines() {
        let trimmed = line.trim_start();
        let line_html = if trimmed.is_empty() {
            String::new()
        } else if trimmed.starts_with('#') {
            format!("<span class='th-comment'>{}</span>", escape_html(line))
        } else if trimmed.starts_with("[[") {
            format!("<span class='th-header2'>{}</span>", escape_html(line))
        } else if trimmed.starts_with('[') {
            format!("<span class='th-header'>{}</span>", escape_html(line))
        } else if let Some(eq) = line.find('=') {
            let key = escape_html(line[..eq].trim_end());
            let val = &line[eq + 1..];
            let space_after_eq = if val.starts_with(' ') { " " } else { "" };
            let hl_val = highlight_toml_value(val.trim_start());
            format!("<span class='th-key'>{key}</span><span class='th-op'> =</span>{space_after_eq}{hl_val}")
        } else {
            escape_html(line)
        };
        out.push_str(&line_html);
        out.push('\n');
    }
    out
}

fn load_saved() -> TomlConfig {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item(STORAGE_KEY).ok().flatten())
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &TomlConfig) {
    if let Ok(json) = serde_json::to_string(cfg) {
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
        {
            let _ = storage.set_item(STORAGE_KEY, &json);
        }
    }
}

// ── Root page ──────────────────────────────────────────────────────────────

#[component]
pub fn ConfigPage() -> impl IntoView {
    let cfg = RwSignal::new(load_saved());

    // Auto-save on every change.
    Effect::new(move |_| save_config(&cfg.get()));

    // Async debounced TOML generation — yields to browser before computing,
    // only the latest generation wins (debounce via generation counter).
    let toml_text = RwSignal::new(cfg.with(|c| c.to_toml()));
    let gen_id = RwSignal::new(0u64);

    Effect::new(move |_| {
        let config = cfg.get();
        let my_id = gen_id.get_untracked() + 1;
        gen_id.set(my_id);
        spawn_local(async move {
            TimeoutFuture::new(100).await; // yield for 100 ms
            if gen_id.get_untracked() == my_id {
                toml_text.set(config.to_toml());
            }
        });
    });

    let preview_el = NodeRef::<html::Pre>::new();
    Effect::new(move |_| {
        let html = highlight_toml(&toml_text.get());
        if let Some(el) = preview_el.get() {
            el.set_inner_html(&html);
        }
    });

    let copied = RwSignal::new(false);

    let do_copy = {
        move |_| {
            let text = toml_text.get();
            let _ = js_sys::eval(&format!("window.copyText({:?})", text));
            copied.set(true);
            // Reset after 2 s via a separate signal tick — no timers in stable Leptos 0.7 without gloo
            let _ = js_sys::eval(
                "setTimeout(function(){ window.__ensiaCopiedClear && window.__ensiaCopiedClear(); }, 2000)"
            );
        }
    };

    let do_download = {
        move |_| {
            let text = toml_text.get();
            let _ = js_sys::eval(&format!(
                "window.downloadText('ensia.toml', {:?})",
                text
            ));
        }
    };

    provide_context(cfg);

    view! {
        <div class="page-wrap config-layout">
            // ── Left: form ──────────────────────────────────────────────
            <div class="config-form">
                <div>
                    <h2>"Config Builder"</h2>
                    <p class="mt-sm">
                        "Build your " <code class="font-mono">"ensia.toml"</code>
                        " visually. Changes are auto-saved to your browser."
                    </p>
                </div>

                <GlobalSection />
                <BcfCard />
                <StrEncCard />
                <ConstEncCard />
                <FlattenCard />
                <SubCard />
                <MbaCard />
                <CsmCard />
                <VecCard />
                <IndirCard />
                <FuncWrapCard />
                <AntiDebugCard />
                <AntiHookCard />
                <AntiClassDumpCard />
                <FuncCallObfCard />
                <SplitBlocksCard />
                <PoliciesSection />
            </div>

            // ── Right: live preview + export ────────────────────────────
            <div class="config-preview">
                <div class="glass card-pad">
                    <div class="flex items-center justify-between mb-sm">
                        <span class="section-chip">"Live Preview"</span>
                        <div class="export-actions">
                            <button class="btn btn-ghost btn-sm" on:click=do_copy>
                                "Copy"
                            </button>
                            <button class="btn btn-primary btn-sm" on:click=do_download>
                                "Download"
                            </button>
                        </div>
                    </div>
                    {move || copied.get().then(|| view! {
                        <p class="copy-feedback">"✓ Copied to clipboard"</p>
                    })}
                    <pre class="code-block toml-preview" node_ref=preview_el></pre>
                </div>
                <div class="glass-alt card-pad">
                    <p class="text-sm text-muted">
                        "Pass this file with:"
                    </p>
                    <pre class="code-block text-xs mt-sm">
"-mllvm -ensia-config=ensia.toml"
                    </pre>
                </div>
            </div>
        </div>
    }
}

// ── Global section ────────────────────────────────────────────────────────

#[component]
fn GlobalSection() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();

    view! {
        <div class="glass card-pad">
            <span class="section-chip">"🌐 Global"</span>
            <div class="config-grid-2">
                <div class="field-group">
                    <label class="field-label">"Preset"</label>
                    <select
                        class="field-input"
                        prop:value=move || cfg.with(|c| c.preset.clone())
                        on:change=move |e| {
                            let v = event_target_value(&e);
                            cfg.update(|c| c.preset = v);
                        }
                    >
                        <option value="low">"low — minimal overhead"</option>
                        <option value="mid">"mid — balanced (recommended)"</option>
                        <option value="high">"high — maximum protection"</option>
                    </select>
                </div>
                <div class="field-group">
                    <label class="field-label">"Seed (hex, optional)"</label>
                    <input
                        type="text"
                        class="field-input mono"
                        placeholder="e.g. 0xDEADBEEF"
                        prop:value=move || cfg.with(|c| c.seed.clone())
                        on:input=move |e| {
                            let v = event_target_value(&e);
                            cfg.update(|c| c.seed = v);
                        }
                    />
                </div>
            </div>
            <div class="flex gap-lg mt-md flex-wrap">
                <ToggleField
                    label="Verbose output"
                    get=Signal::derive(move || cfg.with(|c| c.verbose))
                    set=move |v| cfg.update(|c| c.verbose = v)
                />
                <ToggleField
                    label="Trace mode"
                    get=Signal::derive(move || cfg.with(|c| c.trace))
                    set=move |v| cfg.update(|c| c.trace = v)
                />
                <ToggleField
                    label="Demangle names"
                    get=Signal::derive(move || cfg.with(|c| c.demangle_names))
                    set=move |v| cfg.update(|c| c.demangle_names = v)
                />
            </div>
        </div>
    }
}

// ── BCF ──────────────────────────────────────────────────────────────────

#[component]
fn BcfCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.bcf.enabled));

    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"🔀"</span>
                    "Bogus Control Flow"
                </span>
                <ToggleField
                    label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.bcf.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <div class="config-grid-2">
                    <SliderField
                        label="Probability (%)"
                        min=0 max=100
                        get=Signal::derive(move || cfg.with(|c| c.bcf.probability))
                        set=move |v| cfg.update(|c| c.bcf.probability = v)
                    />
                    <SliderField
                        label="Iterations"
                        min=1 max=5
                        get=Signal::derive(move || cfg.with(|c| c.bcf.iterations))
                        set=move |v| cfg.update(|c| c.bcf.iterations = v)
                    />
                    <SliderField
                        label="Complexity"
                        min=1 max=10
                        get=Signal::derive(move || cfg.with(|c| c.bcf.complexity))
                        set=move |v| cfg.update(|c| c.bcf.complexity = v)
                    />
                </div>
                <div class="flex gap-lg flex-wrap">
                    <ToggleField
                        label="Entropy chain"
                        get=Signal::derive(move || cfg.with(|c| c.bcf.entropy_chain))
                        set=move |v| cfg.update(|c| c.bcf.entropy_chain = v)
                    />
                    <ToggleField
                        label="Junk ASM"
                        get=Signal::derive(move || cfg.with(|c| c.bcf.junk_asm))
                        set=move |v| cfg.update(|c| c.bcf.junk_asm = v)
                    />
                </div>
                {move || cfg.with(|c| c.bcf.junk_asm).then(|| view! {
                    <div class="config-grid-2">
                        <SliderField
                            label="Junk ASM min"
                            min=1 max=8
                            get=Signal::derive(move || cfg.with(|c| c.bcf.junk_asm_min))
                            set=move |v| cfg.update(|c| c.bcf.junk_asm_min = v)
                        />
                        <SliderField
                            label="Junk ASM max"
                            min=2 max=14
                            get=Signal::derive(move || cfg.with(|c| c.bcf.junk_asm_max))
                            set=move |v| cfg.update(|c| c.bcf.junk_asm_max = v)
                        />
                    </div>
                })}
            </div>
        </div>
    }
}

// ── String Encryption ─────────────────────────────────────────────────────

#[component]
fn StrEncCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.str_enc.enabled));

    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"🔒"</span>
                    "String Encryption"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.str_enc.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <SliderField
                    label="Probability (%)"
                    min=0 max=100
                    get=Signal::derive(move || cfg.with(|c| c.str_enc.probability))
                    set=move |v| cfg.update(|c| c.str_enc.probability = v)
                />
                <TagField
                    label="force_content — always encrypt these patterns"
                    placeholder="regex pattern, e.g. SHA256"
                    get=Signal::derive(move || cfg.with(|c| c.str_enc.force_content.clone()))
                    set=move |v| cfg.update(|c| c.str_enc.force_content = v)
                />
                <TagField
                    label="skip_content — never encrypt these patterns"
                    placeholder="regex pattern, e.g. ^Usage:"
                    get=Signal::derive(move || cfg.with(|c| c.str_enc.skip_content.clone()))
                    set=move |v| cfg.update(|c| c.str_enc.skip_content = v)
                />
            </div>
        </div>
    }
}

// ── Constant Encryption ───────────────────────────────────────────────────

#[component]
fn ConstEncCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.const_enc.enabled));

    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"🧮"</span>
                    "Constant Encryption"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.const_enc.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <div class="config-grid-2">
                    <SliderField
                        label="Share count (k)"
                        min=2 max=6
                        get=Signal::derive(move || cfg.with(|c| c.const_enc.share_count))
                        set=move |v| cfg.update(|c| c.const_enc.share_count = v)
                    />
                </div>
                <div class="flex gap-lg flex-wrap">
                    <ToggleField
                        label="Feistel layer"
                        get=Signal::derive(move || cfg.with(|c| c.const_enc.feistel))
                        set=move |v| cfg.update(|c| c.const_enc.feistel = v)
                    />
                    <ToggleField
                        label="Substitute XOR"
                        get=Signal::derive(move || cfg.with(|c| c.const_enc.substitute_xor))
                        set=move |v| cfg.update(|c| c.const_enc.substitute_xor = v)
                    />
                </div>
                {move || cfg.with(|c| c.const_enc.substitute_xor).then(|| view! {
                    <SliderField
                        label="Substitute XOR probability (%)"
                        min=0 max=100
                        get=Signal::derive(move || cfg.with(|c| c.const_enc.substitute_xor_prob))
                        set=move |v| cfg.update(|c| c.const_enc.substitute_xor_prob = v)
                    />
                })}
                <TagField
                    label="force_value — always encrypt (hex literals, e.g. 0x9E3779B9)"
                    placeholder="0x..."
                    get=Signal::derive(move || cfg.with(|c| c.const_enc.force_value.clone()))
                    set=move |v| cfg.update(|c| c.const_enc.force_value = v)
                />
                <TagField
                    label="skip_value — never encrypt (regex, e.g. ^0x0$)"
                    placeholder="^0x0$"
                    get=Signal::derive(move || cfg.with(|c| c.const_enc.skip_value.clone()))
                    set=move |v| cfg.update(|c| c.const_enc.skip_value = v)
                />
            </div>
        </div>
    }
}

// ── Simple pass cards ─────────────────────────────────────────────────────

#[component]
fn FlattenCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="⬛" title="Control Flow Flattening"
            get=Signal::derive(move || cfg.with(|c| c.flattening.enabled))
            set=move |v| cfg.update(|c| c.flattening.enabled = v)
        />
    }
}

#[component]
fn SubCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.substitution.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"➕"</span>
                    "Instruction Substitution"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.substitution.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <SliderField
                    label="Probability (%)"
                    min=0 max=100
                    get=Signal::derive(move || cfg.with(|c| c.substitution.probability))
                    set=move |v| cfg.update(|c| c.substitution.probability = v)
                />
            </div>
        </div>
    }
}

#[component]
fn MbaCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.mba.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"∑"</span>
                    "Mixed Boolean-Arithmetic"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.mba.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <SliderField
                    label="Layers"
                    min=1 max=4
                    get=Signal::derive(move || cfg.with(|c| c.mba.layers))
                    set=move |v| cfg.update(|c| c.mba.layers = v)
                />
                <ToggleField
                    label="Heuristic mode (faster, weaker)"
                    get=Signal::derive(move || cfg.with(|c| c.mba.heuristic))
                    set=move |v| cfg.update(|c| c.mba.heuristic = v)
                />
            </div>
        </div>
    }
}

#[component]
fn CsmCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.csm.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"🌀"</span>
                    "Chaos State Machine"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.csm.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <SliderField
                    label="Warmup iterations"
                    min=16 max=512
                    get=Signal::derive(move || cfg.with(|c| c.csm.warmup))
                    set=move |v| cfg.update(|c| c.csm.warmup = v)
                />
                <ToggleField
                    label="Nested dispatch"
                    get=Signal::derive(move || cfg.with(|c| c.csm.nested_dispatch))
                    set=move |v| cfg.update(|c| c.csm.nested_dispatch = v)
                />
            </div>
        </div>
    }
}

#[component]
fn VecCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.vec_obf.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"⬡"</span>
                    "Vector Obfuscation"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.vec_obf.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <div class="config-grid-2">
                    <SliderField
                        label="Probability (%)"
                        min=0 max=100
                        get=Signal::derive(move || cfg.with(|c| c.vec_obf.probability))
                        set=move |v| cfg.update(|c| c.vec_obf.probability = v)
                    />
                    <div class="field-group">
                        <label class="field-label">"Vector width (bits)"</label>
                        <select
                            class="field-input"
                            prop:value=move || cfg.with(|c| c.vec_obf.width.to_string())
                            on:change=move |e| {
                                let v: u32 = event_target_value(&e).parse().unwrap_or(128);
                                cfg.update(|c| c.vec_obf.width = v);
                            }
                        >
                            <option value="64">"64"</option>
                            <option value="128">"128 (recommended)"</option>
                            <option value="256">"256"</option>
                        </select>
                    </div>
                </div>
                <div class="flex gap-lg flex-wrap">
                    <ToggleField
                        label="Lane shuffle"
                        get=Signal::derive(move || cfg.with(|c| c.vec_obf.shuffle))
                        set=move |v| cfg.update(|c| c.vec_obf.shuffle = v)
                    />
                    <ToggleField
                        label="Lift comparisons"
                        get=Signal::derive(move || cfg.with(|c| c.vec_obf.lift_comparisons))
                        set=move |v| cfg.update(|c| c.vec_obf.lift_comparisons = v)
                    />
                </div>
            </div>
        </div>
    }
}

#[component]
fn IndirCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="↩" title="Indirect Branching"
            get=Signal::derive(move || cfg.with(|c| c.indir_branch.enabled))
            set=move |v| cfg.update(|c| c.indir_branch.enabled = v)
        />
    }
}

#[component]
fn FuncWrapCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.func_wrap.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"📦"</span>
                    "Function Wrapper"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.func_wrap.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <div class="config-grid-2">
                    <SliderField
                        label="Probability (%)"
                        min=0 max=100
                        get=Signal::derive(move || cfg.with(|c| c.func_wrap.probability))
                        set=move |v| cfg.update(|c| c.func_wrap.probability = v)
                    />
                    <SliderField
                        label="Wrapper depth"
                        min=1 max=5
                        get=Signal::derive(move || cfg.with(|c| c.func_wrap.times))
                        set=move |v| cfg.update(|c| c.func_wrap.times = v)
                    />
                </div>
            </div>
        </div>
    }
}

// ── Anti-analysis pass cards ──────────────────────────────────────────────

#[component]
fn AntiDebugCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="\u{1F41B}" title="Anti-Debugging"
            get=Signal::derive(move || cfg.with(|c| c.anti_debugging.enabled))
            set=move |v| cfg.update(|c| c.anti_debugging.enabled = v)
        />
    }
}

#[component]
fn AntiHookCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="\u{1F3A3}" title="Anti-Hooking"
            get=Signal::derive(move || cfg.with(|c| c.anti_hooking.enabled))
            set=move |v| cfg.update(|c| c.anti_hooking.enabled = v)
        />
    }
}

#[component]
fn AntiClassDumpCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="\u{1F50D}" title="Anti-Class Dump (ObjC)"
            get=Signal::derive(move || cfg.with(|c| c.anti_class_dump.enabled))
            set=move |v| cfg.update(|c| c.anti_class_dump.enabled = v)
        />
    }
}

#[component]
fn FuncCallObfCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    view! {
        <SimplePassCard
            icon="\u{1F4DE}" title="Function Call Obfuscation"
            get=Signal::derive(move || cfg.with(|c| c.func_call_obf.enabled))
            set=move |v| cfg.update(|c| c.func_call_obf.enabled = v)
        />
    }
}

#[component]
fn SplitBlocksCard() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let enabled = Signal::derive(move || cfg.with(|c| c.split_blocks.enabled));
    view! {
        <div class="pass-card" class:pass-disabled=move || !enabled.get()>
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">"\u{2702}"</span>
                    "Basic Block Splitting"
                </span>
                <ToggleField label=""
                    get=enabled
                    set=move |v| cfg.update(|c| c.split_blocks.enabled = v)
                />
            </div>
            <div class="pass-card-body">
                <SliderField
                    label="Probability (%)"
                    min=0 max=100
                    get=Signal::derive(move || cfg.with(|c| c.split_blocks.probability))
                    set=move |v| cfg.update(|c| c.split_blocks.probability = v)
                />
            </div>
        </div>
    }
}

// ── Policy rules ──────────────────────────────────────────────────────────

#[component]
fn PoliciesSection() -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();

    let add_policy = move |_| {
        cfg.update(|c| {
            let id = c.next_policy_id;
            c.next_policy_id += 1;
            c.policies.push(PolicyCfg::new(id));
        });
    };

    view! {
        <div class="glass card-pad">
            <div class="flex items-center justify-between mb-md">
                <span class="section-chip">"⚙ Per-Function Policies"</span>
                <button class="btn btn-ghost btn-sm" on:click=add_policy>
                    "+ Add Policy"
                </button>
            </div>
            <p class="text-sm text-muted mb-md">
                "Policy rules match functions by regex and override any global pass settings.
                 Rules are evaluated top-to-bottom; the last match wins."
            </p>

            {move || {
                let policies = cfg.with(|c| c.policies.clone());
                if policies.is_empty() {
                    view! {
                        <p class="text-sm text-muted">"No policies yet. Add one above."</p>
                    }.into_any()
                } else {
                    policies.into_iter().enumerate().map(|(idx, pol)| {
                        view! { <PolicyCard idx=idx policy=pol /> }
                    }).collect_view().into_any()
                }
            }}
        </div>
    }
}

#[component]
fn PolicyCard(idx: usize, policy: PolicyCfg) -> impl IntoView {
    let cfg = expect_context::<RwSignal<TomlConfig>>();
    let id = policy.id;

    let remove = move |_| {
        cfg.update(|c| c.policies.retain(|p| p.id != id));
    };

    let update_field = move |f: fn(&mut PolicyCfg, String), val: String| {
        cfg.update(|c| {
            if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) {
                f(p, val);
            }
        });
    };

    view! {
        <div class="policy-rule-card">
            <div class="policy-rule-header">
                <span class="policy-rule-num">"Policy #" {idx + 1}</span>
                <button class="btn btn-danger btn-sm btn-icon" on:click=remove title="Remove">
                    "✕"
                </button>
            </div>

            <div class="config-grid-2">
                <div class="field-group">
                    <label class="field-label">"Module (regex)"</label>
                    <input type="text" class="field-input mono"
                        placeholder="e.g. .*my_crate.*"
                        prop:value=policy.module.clone()
                        on:input=move |e| {
                            let v = event_target_value(&e);
                            update_field(|p, v| p.module = v, v);
                        }
                    />
                </div>
                <div class="field-group">
                    <label class="field-label">"Function (regex)"</label>
                    <input type="text" class="field-input mono"
                        placeholder="e.g. ^main$"
                        prop:value=policy.function.clone()
                        on:input=move |e| {
                            let v = event_target_value(&e);
                            update_field(|p, v| p.function = v, v);
                        }
                    />
                </div>
            </div>

            <div class="field-group">
                <label class="field-label">"Preset override (optional)"</label>
                <select class="field-input"
                    prop:value=policy.preset.clone()
                    on:change=move |e| {
                        let v = event_target_value(&e);
                        update_field(|p, v| p.preset = v, v);
                    }
                >
                    <option value="">"— inherit global preset —"</option>
                    <option value="low">"low"</option>
                    <option value="mid">"mid"</option>
                    <option value="high">"high"</option>
                </select>
            </div>

            // ── Pass enable/disable overrides (all 15) ──────────────────
            <div>
                <p class="field-label mb-sm">"Pass enable overrides"
                    <span class="text-muted text-xs"> " (Inherit / On / Off)"</span>
                </p>
                <div class="policy-overrides-grid">
                    <TriToggle label="BCF"
                        val=policy.bcf_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_enabled = v; } })
                    />
                    <TriToggle label="Substitution"
                        val=policy.sub_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.sub_enabled = v; } })
                    />
                    <TriToggle label="MBA"
                        val=policy.mba_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.mba_enabled = v; } })
                    />
                    <TriToggle label="Str Enc"
                        val=policy.str_enc_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.str_enc_enabled = v; } })
                    />
                    <TriToggle label="Const Enc"
                        val=policy.const_enc_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.const_enc_enabled = v; } })
                    />
                    <TriToggle label="Flattening"
                        val=policy.flatten_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.flatten_enabled = v; } })
                    />
                    <TriToggle label="CSM"
                        val=policy.csm_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.csm_enabled = v; } })
                    />
                    <TriToggle label="Vec Obf"
                        val=policy.vec_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.vec_enabled = v; } })
                    />
                    <TriToggle label="Indir Branch"
                        val=policy.indir_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.indir_enabled = v; } })
                    />
                    <TriToggle label="Func Wrap"
                        val=policy.fw_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.fw_enabled = v; } })
                    />
                    <TriToggle label="AntiDebug"
                        val=policy.anti_debug_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.anti_debug_enabled = v; } })
                    />
                    <TriToggle label="AntiHook"
                        val=policy.anti_hook_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.anti_hook_enabled = v; } })
                    />
                    <TriToggle label="AntiClassDump"
                        val=policy.anti_class_dump_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.anti_class_dump_enabled = v; } })
                    />
                    <TriToggle label="CallObf"
                        val=policy.func_call_obf_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.func_call_obf_enabled = v; } })
                    />
                    <TriToggle label="SplitBlocks"
                        val=policy.split_blocks_enabled
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.split_blocks_enabled = v; } })
                    />
                </div>
            </div>

            // ── BCF sub-options ──────────────────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"BCF sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="probability (%)" min=0 max=100
                        val=policy.bcf_probability
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_probability = v; } })
                    />
                    <PolicyNumField label="iterations" min=1 max=5
                        val=policy.bcf_iterations
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_iterations = v; } })
                    />
                    <PolicyNumField label="complexity" min=1 max=10
                        val=policy.bcf_complexity
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_complexity = v; } })
                    />
                    <PolicyNumField label="junk_asm_min" min=1 max=8
                        val=policy.bcf_junk_asm_min
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_junk_asm_min = v; } })
                    />
                    <PolicyNumField label="junk_asm_max" min=2 max=14
                        val=policy.bcf_junk_asm_max
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_junk_asm_max = v; } })
                    />
                </div>
                <div class="flex gap-sm flex-wrap mt-sm">
                    <TriToggle label="entropy_chain"
                        val=policy.bcf_entropy_chain
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_entropy_chain = v; } })
                    />
                    <TriToggle label="junk_asm"
                        val=policy.bcf_junk_asm
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.bcf_junk_asm = v; } })
                    />
                </div>
            </div>

            // ── Substitution sub-options ─────────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Substitution sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="probability (%)" min=0 max=100
                        val=policy.sub_probability
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.sub_probability = v; } })
                    />
                </div>
            </div>

            // ── MBA sub-options ──────────────────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"MBA sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="layers" min=1 max=4
                        val=policy.mba_layers
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.mba_layers = v; } })
                    />
                </div>
                <div class="flex gap-sm flex-wrap mt-sm">
                    <TriToggle label="heuristic"
                        val=policy.mba_heuristic
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.mba_heuristic = v; } })
                    />
                </div>
            </div>

            // ── CSM sub-options ──────────────────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Chaos State Machine sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="warmup" min=16 max=512
                        val=policy.csm_warmup
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.csm_warmup = v; } })
                    />
                </div>
                <div class="flex gap-sm flex-wrap mt-sm">
                    <TriToggle label="nested_dispatch"
                        val=policy.csm_nested_dispatch
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.csm_nested_dispatch = v; } })
                    />
                </div>
            </div>

            // ── Vector obfuscation sub-options ───────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Vector Obfuscation sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="probability (%)" min=0 max=100
                        val=policy.vec_probability
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.vec_probability = v; } })
                    />
                </div>
                <div class="flex gap-sm flex-wrap mt-sm">
                    <TriToggle label="shuffle"
                        val=policy.vec_shuffle
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.vec_shuffle = v; } })
                    />
                    <TriToggle label="lift_comparisons"
                        val=policy.vec_lift_comparisons
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.vec_lift_comparisons = v; } })
                    />
                </div>
            </div>

            // ── Constant encryption sub-options ──────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Constant Encryption sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="share_count (k)" min=2 max=6
                        val=policy.const_enc_share_count
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.const_enc_share_count = v; } })
                    />
                    <PolicyNumField label="substitute_xor_prob (%)" min=0 max=100
                        val=policy.const_enc_substitute_xor_prob
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.const_enc_substitute_xor_prob = v; } })
                    />
                </div>
                <div class="flex gap-sm flex-wrap mt-sm">
                    <TriToggle label="feistel"
                        val=policy.const_enc_feistel
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.const_enc_feistel = v; } })
                    />
                    <TriToggle label="substitute_xor"
                        val=policy.const_enc_substitute_xor
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.const_enc_substitute_xor = v; } })
                    />
                </div>
            </div>

            // ── Function wrapper sub-options ─────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Function Wrapper sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="probability (%)" min=0 max=100
                        val=policy.fw_probability
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.fw_probability = v; } })
                    />
                    <PolicyNumField label="times (depth)" min=1 max=5
                        val=policy.fw_times
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.fw_times = v; } })
                    />
                </div>
            </div>

            // ── Split blocks sub-options ─────────────────────────────────
            <div class="policy-sub-section">
                <p class="field-label mb-sm">"Split Basic Blocks sub-options"</p>
                <div class="config-grid-2">
                    <PolicyNumField label="probability (%)" min=0 max=100
                        val=policy.split_blocks_probability
                        set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.split_blocks_probability = v; } })
                    />
                </div>
            </div>

            // ── String encryption content overrides ──────────────────────
            <TagField
                label="force_content — always encrypt these patterns in this scope"
                placeholder="regex, e.g. SECRET"
                get=Signal::derive(move || cfg.with(|c|
                    c.policies.iter().find(|p| p.id == id)
                        .map(|p| p.str_force.clone()).unwrap_or_default()))
                set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.str_force = v; } })
            />
            <TagField
                label="skip_content — never encrypt these patterns in this scope"
                placeholder="regex, e.g. ^Usage:"
                get=Signal::derive(move || cfg.with(|c|
                    c.policies.iter().find(|p| p.id == id)
                        .map(|p| p.str_skip.clone()).unwrap_or_default()))
                set=move |v| cfg.update(|c| { if let Some(p) = c.policies.iter_mut().find(|p| p.id == id) { p.str_skip = v; } })
            />
        </div>
    }
}

// ── Reusable form primitives ───────────────────────────────────────────────

#[component]
fn ToggleField(
    label: &'static str,
    get: Signal<bool>,
    set: impl Fn(bool) + 'static,
) -> impl IntoView {
    view! {
        <label class="toggle-wrap">
            <div class="toggle-switch">
                <input
                    type="checkbox"
                    prop:checked=move || get.get()
                    on:change=move |e| set(event_target_checked(&e))
                />
                <span class="toggle-track"></span>
            </div>
            {(!label.is_empty()).then_some(view! {
                <span class="text-sm">{label}</span>
            })}
        </label>
    }
}

#[component]
fn SliderField(
    label: &'static str,
    min: u32,
    max: u32,
    get: Signal<u32>,
    set: impl Fn(u32) + 'static,
) -> impl IntoView {
    let pct = Signal::derive(move || {
        let v = get.get();
        let range = max - min;
        if range == 0 { 50.0 } else { (v - min) as f64 / range as f64 * 100.0 }
    });

    view! {
        <div class="field-group">
            <label class="field-label">{label}</label>
            <div class="slider-row">
                <input
                    type="range"
                    min=min max=max
                    prop:value=move || get.get()
                    style=move || format!("--pct:{}%", pct.get())
                    on:input=move |e| {
                        let v: u32 = event_target_value(&e).parse().unwrap_or(min);
                        set(v);
                    }
                />
                <span class="slider-val">{move || get.get()}</span>
            </div>
        </div>
    }
}

#[component]
fn TagField(
    label: &'static str,
    placeholder: &'static str,
    get: Signal<Vec<String>>,
    set: impl Fn(Vec<String>) + 'static + Clone + Send,
) -> impl IntoView {
    let input_val = RwSignal::new(String::new());

    let do_add = {
        let get = get.clone();
        let set = set.clone();
        move || {
            let val = input_val.get();
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                let mut tags = get.get();
                if !tags.contains(&trimmed) {
                    tags.push(trimmed);
                    set(tags);
                }
                input_val.set(String::new());
            }
        }
    };

    let add_on_click = {
        let do_add = do_add.clone();
        move |_: web_sys::MouseEvent| do_add()
    };

    let add_on_key = move |e: web_sys::KeyboardEvent| {
        if e.key() == "Enter" { do_add(); }
    };

    view! {
        <div class="field-group">
            <label class="field-label">{label}</label>
            <div class="tag-area">
                {move || get.get().into_iter().enumerate().map(|(i, tag)| {
                    let set = set.clone();
                    let get = get.clone();
                    view! {
                        <span class="tag-pill">
                            {tag}
                            <button
                                class="tag-pill-del"
                                title="Remove"
                                on:click=move |_: web_sys::MouseEvent| {
                                    let mut tags = get.get();
                                    tags.remove(i);
                                    set(tags);
                                }
                            >"\u{00D7}"</button>
                        </span>
                    }
                }).collect_view()}
            </div>
            <div class="tag-add-row">
                <input
                    type="text"
                    class="field-input"
                    placeholder=placeholder
                    prop:value=move || input_val.get()
                    on:input=move |e| input_val.set(event_target_value(&e))
                    on:keydown=add_on_key
                />
                <button class="btn btn-ghost btn-sm" on:click=add_on_click>"Add"</button>
            </div>
        </div>
    }
}

/// Numeric override input for policies. val=None means "inherit"; entering a value enables it.
#[component]
fn PolicyNumField(
    label: &'static str,
    min: u32,
    max: u32,
    val: Option<u32>,
    set: impl Fn(Option<u32>) + 'static,
) -> impl IntoView {
    let current = RwSignal::new(val.map(|v| v.to_string()).unwrap_or_default());

    view! {
        <div class="field-group">
            <label class="field-label">{label}
                <span class="text-muted text-xs">" (blank = inherit)"</span>
            </label>
            <input
                type="number"
                class="field-input mono"
                min=min max=max
                placeholder="inherit"
                prop:value=move || current.get()
                on:input=move |e| {
                    let s = event_target_value(&e);
                    current.set(s.clone());
                    if s.trim().is_empty() {
                        set(None);
                    } else if let Ok(n) = s.trim().parse::<u32>() {
                        set(Some(n.clamp(min, max)));
                    }
                }
            />
        </div>
    }
}

/// Three-way toggle for policy pass overrides: None | Some(true) | Some(false)
#[component]
fn TriToggle(
    label: &'static str,
    val: Option<bool>,
    set: impl Fn(Option<bool>) + 'static,
) -> impl IntoView {
    let current = RwSignal::new(val);

    let cycle = move |_| {
        let next = match current.get() {
            None        => Some(true),
            Some(true)  => Some(false),
            Some(false) => None,
        };
        current.set(next);
        set(next);
    };

    view! {
        <button
            class="btn btn-sm"
            class:btn-ghost=move || current.get().is_none()
            class:btn-primary=move || current.get() == Some(true)
            class:btn-danger=move || current.get() == Some(false)
            on:click=cycle
            title=move || match current.get() {
                None        => "Inherit (click to enable)",
                Some(true)  => "Enabled (click to disable)",
                Some(false) => "Disabled (click to inherit)",
            }
        >
            {move || match current.get() {
                None        => format!("{} —", label),
                Some(true)  => format!("{} ✓", label),
                Some(false) => format!("{} ✕", label),
            }}
        </button>
    }
}

/// Minimal on/off pass card (no sub-options).
#[component]
fn SimplePassCard(
    icon: &'static str,
    title: &'static str,
    get: Signal<bool>,
    set: impl Fn(bool) + 'static,
) -> impl IntoView {
    view! {
        <div class="pass-card">
            <div class="pass-card-header">
                <span class="pass-card-title">
                    <span class="pass-card-icon">{icon}</span>
                    {title}
                </span>
                <ToggleField label="" get=get set=set />
            </div>
        </div>
    }
}
