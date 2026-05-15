use serde::{Deserialize, Serialize};

// ── Per-pass configs ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BcfCfg {
    pub enabled: bool,
    pub probability: u32,
    pub iterations: u32,
    pub complexity: u32,
    pub entropy_chain: bool,
    pub junk_asm: bool,
    pub junk_asm_min: u32,
    pub junk_asm_max: u32,
}
impl Default for BcfCfg {
    fn default() -> Self {
        Self { enabled: true, probability: 50, iterations: 1, complexity: 3,
               entropy_chain: false, junk_asm: false, junk_asm_min: 1, junk_asm_max: 4 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StrEncCfg {
    pub enabled: bool,
    pub probability: u32,
    pub force_content: Vec<String>,
    pub skip_content: Vec<String>,
}
impl Default for StrEncCfg {
    fn default() -> Self {
        Self { enabled: true, probability: 80, force_content: vec![], skip_content: vec![] }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConstEncCfg {
    pub enabled: bool,
    pub share_count: u32,
    pub feistel: bool,
    pub substitute_xor: bool,
    pub substitute_xor_prob: u32,
    pub force_value: Vec<String>,
    pub skip_value: Vec<String>,
}
impl Default for ConstEncCfg {
    fn default() -> Self {
        Self { enabled: true, share_count: 3, feistel: false,
               substitute_xor: false, substitute_xor_prob: 40,
               force_value: vec![], skip_value: vec!["^0x0$".into(), "^0x1$".into()] }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct SimpleCfg { pub enabled: bool }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SplitBlocksCfg { pub enabled: bool, pub probability: u32 }
impl Default for SplitBlocksCfg {
    fn default() -> Self { Self { enabled: false, probability: 50 } }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SubCfg { pub enabled: bool, pub probability: u32 }
impl Default for SubCfg {
    fn default() -> Self { Self { enabled: true, probability: 60 } }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MbaCfg { pub enabled: bool, pub layers: u32, pub heuristic: bool }
impl Default for MbaCfg {
    fn default() -> Self { Self { enabled: true, layers: 1, heuristic: false } }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CsmCfg { pub enabled: bool, pub warmup: u32, pub nested_dispatch: bool }
impl Default for CsmCfg {
    fn default() -> Self { Self { enabled: false, warmup: 64, nested_dispatch: false } }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VecObfCfg {
    pub enabled: bool,
    pub probability: u32,
    pub width: u32,
    pub shuffle: bool,
    pub lift_comparisons: bool,
}
impl Default for VecObfCfg {
    fn default() -> Self {
        Self { enabled: false, probability: 50, width: 128, shuffle: false, lift_comparisons: false }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FuncWrapCfg { pub enabled: bool, pub probability: u32, pub times: u32 }
impl Default for FuncWrapCfg {
    fn default() -> Self { Self { enabled: false, probability: 50, times: 1 } }
}

// ── Policy rule ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyCfg {
    pub id: usize,
    pub module: String,
    pub function: String,
    pub preset: String,

    // ── per-pass enable overrides (all 15 passes) ────────────────────────
    pub bcf_enabled:           Option<bool>,
    pub sub_enabled:           Option<bool>,
    pub mba_enabled:           Option<bool>,
    pub str_enc_enabled:       Option<bool>,
    pub const_enc_enabled:     Option<bool>,
    pub flatten_enabled:       Option<bool>,
    pub csm_enabled:           Option<bool>,
    pub vec_enabled:           Option<bool>,
    pub indir_enabled:         Option<bool>,
    pub fw_enabled:            Option<bool>,
    pub anti_debug_enabled:    Option<bool>,
    pub anti_hook_enabled:     Option<bool>,
    pub anti_class_dump_enabled: Option<bool>,
    pub func_call_obf_enabled: Option<bool>,
    pub split_blocks_enabled:  Option<bool>,

    // ── BCF overrides ────────────────────────────────────────────────────
    pub bcf_probability:   Option<u32>,
    pub bcf_iterations:    Option<u32>,
    pub bcf_complexity:    Option<u32>,
    pub bcf_entropy_chain: Option<bool>,
    pub bcf_junk_asm:      Option<bool>,
    pub bcf_junk_asm_min:  Option<u32>,
    pub bcf_junk_asm_max:  Option<u32>,

    // ── Substitution overrides ───────────────────────────────────────────
    pub sub_probability:   Option<u32>,

    // ── MBA overrides ────────────────────────────────────────────────────
    pub mba_layers:        Option<u32>,
    pub mba_heuristic:     Option<bool>,

    // ── CSM overrides ────────────────────────────────────────────────────
    pub csm_warmup:        Option<u32>,
    pub csm_nested_dispatch: Option<bool>,

    // ── Vector obfuscation overrides ─────────────────────────────────────
    pub vec_probability:      Option<u32>,
    pub vec_shuffle:          Option<bool>,
    pub vec_lift_comparisons: Option<bool>,

    // ── Constant encryption overrides ────────────────────────────────────
    pub const_enc_share_count:      Option<u32>,
    pub const_enc_feistel:          Option<bool>,
    pub const_enc_substitute_xor:   Option<bool>,
    pub const_enc_substitute_xor_prob: Option<u32>,

    // ── Function wrapper overrides ───────────────────────────────────────
    pub fw_probability:  Option<u32>,
    pub fw_times:        Option<u32>,

    // ── Split blocks overrides ───────────────────────────────────────────
    pub split_blocks_probability: Option<u32>,

    // ── String encryption content overrides ─────────────────────────────
    pub str_force: Vec<String>,
    pub str_skip:  Vec<String>,
}
impl PolicyCfg {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            module: ".*".into(),
            function: "".into(),
            preset: "".into(),
            // pass enable overrides
            bcf_enabled: None, sub_enabled: None, mba_enabled: None,
            str_enc_enabled: None, const_enc_enabled: None, flatten_enabled: None,
            csm_enabled: None, vec_enabled: None, indir_enabled: None, fw_enabled: None,
            anti_debug_enabled: None, anti_hook_enabled: None,
            anti_class_dump_enabled: None, func_call_obf_enabled: None,
            split_blocks_enabled: None,
            // BCF
            bcf_probability: None, bcf_iterations: None, bcf_complexity: None,
            bcf_entropy_chain: None, bcf_junk_asm: None,
            bcf_junk_asm_min: None, bcf_junk_asm_max: None,
            // Substitution
            sub_probability: None,
            // MBA
            mba_layers: None, mba_heuristic: None,
            // CSM
            csm_warmup: None, csm_nested_dispatch: None,
            // Vector
            vec_probability: None, vec_shuffle: None, vec_lift_comparisons: None,
            // Constant encryption
            const_enc_share_count: None, const_enc_feistel: None,
            const_enc_substitute_xor: None, const_enc_substitute_xor_prob: None,
            // Function wrapper
            fw_probability: None, fw_times: None,
            // Split blocks
            split_blocks_probability: None,
            // String content
            str_force: vec![], str_skip: vec![],
        }
    }
}

// ── Root config ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TomlConfig {
    pub preset: String,
    pub seed: String,
    pub verbose: bool,
    pub trace: bool,
    pub demangle_names: bool,
    pub bcf:         BcfCfg,
    pub str_enc:     StrEncCfg,
    pub const_enc:   ConstEncCfg,
    pub flattening:  SimpleCfg,
    pub substitution:SubCfg,
    pub mba:         MbaCfg,
    pub csm:         CsmCfg,
    pub vec_obf:     VecObfCfg,
    pub indir_branch:    SimpleCfg,
    pub func_wrap:       FuncWrapCfg,
    pub anti_debugging:  SimpleCfg,
    pub anti_hooking:    SimpleCfg,
    pub anti_class_dump: SimpleCfg,
    pub func_call_obf:   SimpleCfg,
    pub split_blocks:    SplitBlocksCfg,
    pub policies:        Vec<PolicyCfg>,
    pub next_policy_id: usize,
}

impl Default for TomlConfig {
    fn default() -> Self {
        Self {
            preset: "mid".into(),
            seed: "".into(),
            verbose: true,
            trace: false,
            demangle_names: true,
            bcf: Default::default(),
            str_enc: Default::default(),
            const_enc: Default::default(),
            flattening: SimpleCfg { enabled: true },
            substitution: Default::default(),
            mba: Default::default(),
            csm: Default::default(),
            vec_obf: Default::default(),
            indir_branch: SimpleCfg { enabled: false },
            func_wrap: Default::default(),
            anti_debugging:  SimpleCfg { enabled: false },
            anti_hooking:    SimpleCfg { enabled: false },
            anti_class_dump: SimpleCfg { enabled: false },
            func_call_obf:   SimpleCfg { enabled: false },
            split_blocks:    Default::default(),
            policies: vec![],
            next_policy_id: 0,
        }
    }
}

// ── TOML serializer ───────────────────────────────────────────────────────

fn toml_arr(v: &[String]) -> String {
    let items = v.iter().map(|s| format!("{:?}", s)).collect::<Vec<_>>().join(", ");
    format!("[{}]", items)
}

fn opt_bool_line(key: &str, v: Option<bool>) -> String {
    match v {
        Some(b) => format!("{} = {}\n", key, b),
        None => String::new(),
    }
}
fn opt_u32_line(key: &str, v: Option<u32>) -> String {
    match v {
        Some(n) => format!("{} = {}\n", key, n),
        None => String::new(),
    }
}

impl TomlConfig {
    pub fn to_toml(&self) -> String {
        let mut s = String::new();

        // [global]
        s.push_str("[global]\n");
        s.push_str(&format!("preset = \"{}\"\n", self.preset));
        if !self.seed.is_empty() {
            s.push_str(&format!("seed = {}\n", self.seed));
        }
        if self.verbose          { s.push_str("verbose = true\n"); }
        if self.trace            { s.push_str("trace = true\n"); }
        if !self.demangle_names  { s.push_str("demangle_names = false\n"); }
        s.push('\n');

        // [passes.bcf]
        s.push_str("[passes.bcf]\n");
        s.push_str(&format!("enabled = {}\n", self.bcf.enabled));
        if self.bcf.enabled {
            s.push_str(&format!("probability = {}\n", self.bcf.probability));
            s.push_str(&format!("iterations = {}\n", self.bcf.iterations));
            s.push_str(&format!("complexity = {}\n", self.bcf.complexity));
            if self.bcf.entropy_chain { s.push_str("entropy_chain = true\n"); }
            if self.bcf.junk_asm {
                s.push_str("junk_asm = true\n");
                s.push_str(&format!("junk_asm_min = {}\n", self.bcf.junk_asm_min));
                s.push_str(&format!("junk_asm_max = {}\n", self.bcf.junk_asm_max));
            }
        }
        s.push('\n');

        // [passes.string_encryption]
        s.push_str("[passes.string_encryption]\n");
        s.push_str(&format!("enabled = {}\n", self.str_enc.enabled));
        if self.str_enc.enabled {
            s.push_str(&format!("probability = {}\n", self.str_enc.probability));
            if !self.str_enc.force_content.is_empty() {
                s.push_str(&format!("force_content = {}\n", toml_arr(&self.str_enc.force_content)));
            }
            if !self.str_enc.skip_content.is_empty() {
                s.push_str(&format!("skip_content = {}\n", toml_arr(&self.str_enc.skip_content)));
            }
        }
        s.push('\n');

        // [passes.constant_encryption]
        s.push_str("[passes.constant_encryption]\n");
        s.push_str(&format!("enabled = {}\n", self.const_enc.enabled));
        if self.const_enc.enabled {
            s.push_str(&format!("share_count = {}\n", self.const_enc.share_count));
            if self.const_enc.feistel { s.push_str("feistel = true\n"); }
            if self.const_enc.substitute_xor {
                s.push_str("substitute_xor = true\n");
                s.push_str(&format!("substitute_xor_prob = {}\n", self.const_enc.substitute_xor_prob));
            }
            if !self.const_enc.force_value.is_empty() {
                s.push_str(&format!("force_value = {}\n", toml_arr(&self.const_enc.force_value)));
            }
            if !self.const_enc.skip_value.is_empty() {
                s.push_str(&format!("skip_value = {}\n", toml_arr(&self.const_enc.skip_value)));
            }
        }
        s.push('\n');

        // [passes.flattening]
        s.push_str("[passes.flattening]\n");
        s.push_str(&format!("enabled = {}\n\n", self.flattening.enabled));

        // [passes.substitution]
        s.push_str("[passes.substitution]\n");
        s.push_str(&format!("enabled = {}\n", self.substitution.enabled));
        if self.substitution.enabled {
            s.push_str(&format!("probability = {}\n", self.substitution.probability));
        }
        s.push('\n');

        // [passes.mba]
        s.push_str("[passes.mba]\n");
        s.push_str(&format!("enabled = {}\n", self.mba.enabled));
        if self.mba.enabled {
            s.push_str(&format!("layers = {}\n", self.mba.layers));
            if self.mba.heuristic { s.push_str("heuristic = true\n"); }
        }
        s.push('\n');

        // [passes.chaos_state_machine]
        s.push_str("[passes.chaos_state_machine]\n");
        s.push_str(&format!("enabled = {}\n", self.csm.enabled));
        if self.csm.enabled {
            s.push_str(&format!("warmup = {}\n", self.csm.warmup));
            if self.csm.nested_dispatch { s.push_str("nested_dispatch = true\n"); }
        }
        s.push('\n');

        // [passes.vector_obfuscation]
        s.push_str("[passes.vector_obfuscation]\n");
        s.push_str(&format!("enabled = {}\n", self.vec_obf.enabled));
        if self.vec_obf.enabled {
            s.push_str(&format!("probability = {}\n", self.vec_obf.probability));
            s.push_str(&format!("width = {}\n", self.vec_obf.width));
            if self.vec_obf.shuffle { s.push_str("shuffle = true\n"); }
            if self.vec_obf.lift_comparisons { s.push_str("lift_comparisons = true\n"); }
        }
        s.push('\n');

        // [passes.indirect_branch]
        s.push_str("[passes.indirect_branch]\n");
        s.push_str(&format!("enabled = {}\n\n", self.indir_branch.enabled));

        // [passes.function_wrapper]
        s.push_str("[passes.function_wrapper]\n");
        s.push_str(&format!("enabled = {}\n", self.func_wrap.enabled));
        if self.func_wrap.enabled {
            s.push_str(&format!("probability = {}\n", self.func_wrap.probability));
            s.push_str(&format!("times = {}\n", self.func_wrap.times));
        }
        s.push('\n');

        // [passes.anti_debugging]
        if self.anti_debugging.enabled {
            s.push_str("[passes.anti_debugging]\nenabled = true\n\n");
        }

        // [passes.anti_hooking]
        if self.anti_hooking.enabled {
            s.push_str("[passes.anti_hooking]\nenabled = true\n\n");
        }

        // [passes.anti_class_dump]
        if self.anti_class_dump.enabled {
            s.push_str("[passes.anti_class_dump]\nenabled = true\n\n");
        }

        // [passes.func_call_obf]
        if self.func_call_obf.enabled {
            s.push_str("[passes.func_call_obf]\nenabled = true\n\n");
        }

        // [passes.split_basic_blocks]
        if self.split_blocks.enabled {
            s.push_str("[passes.split_basic_blocks]\nenabled = true\n");
            s.push_str(&format!("probability = {}\n\n", self.split_blocks.probability));
        }

        // [[policy]] entries
        for pol in &self.policies {
            s.push_str("\n[[policy]]\n");
            s.push_str(&format!("module = {:?}\n", pol.module));
            s.push_str(&format!("function = {:?}\n", pol.function));
            if !pol.preset.is_empty() {
                s.push_str(&format!("preset = {:?}\n", pol.preset));
            }
            // enable/disable overrides for all 15 passes
            s.push_str(&opt_bool_line("passes.bcf.enabled",                   pol.bcf_enabled));
            s.push_str(&opt_bool_line("passes.substitution.enabled",          pol.sub_enabled));
            s.push_str(&opt_bool_line("passes.mba.enabled",                   pol.mba_enabled));
            s.push_str(&opt_bool_line("passes.string_encryption.enabled",     pol.str_enc_enabled));
            s.push_str(&opt_bool_line("passes.constant_encryption.enabled",   pol.const_enc_enabled));
            s.push_str(&opt_bool_line("passes.flattening.enabled",            pol.flatten_enabled));
            s.push_str(&opt_bool_line("passes.chaos_state_machine.enabled",   pol.csm_enabled));
            s.push_str(&opt_bool_line("passes.vector_obfuscation.enabled",    pol.vec_enabled));
            s.push_str(&opt_bool_line("passes.indirect_branch.enabled",       pol.indir_enabled));
            s.push_str(&opt_bool_line("passes.function_wrapper.enabled",      pol.fw_enabled));
            s.push_str(&opt_bool_line("passes.anti_debugging.enabled",        pol.anti_debug_enabled));
            s.push_str(&opt_bool_line("passes.anti_hooking.enabled",          pol.anti_hook_enabled));
            s.push_str(&opt_bool_line("passes.anti_class_dump.enabled",       pol.anti_class_dump_enabled));
            s.push_str(&opt_bool_line("passes.func_call_obf.enabled",         pol.func_call_obf_enabled));
            s.push_str(&opt_bool_line("passes.split_basic_blocks.enabled",    pol.split_blocks_enabled));
            // BCF sub-options
            s.push_str(&opt_u32_line("passes.bcf.probability",    pol.bcf_probability));
            s.push_str(&opt_u32_line("passes.bcf.iterations",     pol.bcf_iterations));
            s.push_str(&opt_u32_line("passes.bcf.complexity",     pol.bcf_complexity));
            s.push_str(&opt_bool_line("passes.bcf.entropy_chain", pol.bcf_entropy_chain));
            s.push_str(&opt_bool_line("passes.bcf.junk_asm",      pol.bcf_junk_asm));
            s.push_str(&opt_u32_line("passes.bcf.junk_asm_min",   pol.bcf_junk_asm_min));
            s.push_str(&opt_u32_line("passes.bcf.junk_asm_max",   pol.bcf_junk_asm_max));
            // Substitution
            s.push_str(&opt_u32_line("passes.substitution.probability", pol.sub_probability));
            // MBA
            s.push_str(&opt_u32_line("passes.mba.layers",     pol.mba_layers));
            s.push_str(&opt_bool_line("passes.mba.heuristic", pol.mba_heuristic));
            // CSM
            s.push_str(&opt_u32_line("passes.chaos_state_machine.warmup",        pol.csm_warmup));
            s.push_str(&opt_bool_line("passes.chaos_state_machine.nested_dispatch", pol.csm_nested_dispatch));
            // Vector obfuscation
            s.push_str(&opt_u32_line("passes.vector_obfuscation.probability",        pol.vec_probability));
            s.push_str(&opt_bool_line("passes.vector_obfuscation.shuffle",           pol.vec_shuffle));
            s.push_str(&opt_bool_line("passes.vector_obfuscation.lift_comparisons",  pol.vec_lift_comparisons));
            // Constant encryption
            s.push_str(&opt_u32_line("passes.constant_encryption.share_count",          pol.const_enc_share_count));
            s.push_str(&opt_bool_line("passes.constant_encryption.feistel",             pol.const_enc_feistel));
            s.push_str(&opt_bool_line("passes.constant_encryption.substitute_xor",      pol.const_enc_substitute_xor));
            s.push_str(&opt_u32_line("passes.constant_encryption.substitute_xor_prob",  pol.const_enc_substitute_xor_prob));
            // Function wrapper
            s.push_str(&opt_u32_line("passes.function_wrapper.probability", pol.fw_probability));
            s.push_str(&opt_u32_line("passes.function_wrapper.times",       pol.fw_times));
            // Split blocks
            s.push_str(&opt_u32_line("passes.split_basic_blocks.probability", pol.split_blocks_probability));
            // String encryption content filters
            if !pol.str_force.is_empty() {
                s.push_str(&format!("passes.string_encryption.force_content = {}\n",
                    toml_arr(&pol.str_force)));
            }
            if !pol.str_skip.is_empty() {
                s.push_str(&format!("passes.string_encryption.skip_content = {}\n",
                    toml_arr(&pol.str_skip)));
            }
        }

        s
    }
}
