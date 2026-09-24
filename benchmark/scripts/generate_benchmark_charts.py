#!/usr/bin/env python3
"""
generate_benchmark_charts.py
====================================================================================
Generates SVG benchmark charts for Ensia's web dashboard with Dual-Theme (Dark & Light)
support from benchmark/results/full_deobf_benchmark.csv
====================================================================================
"""

import csv
import os
import shutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

CSV_PATH = "benchmark/results/full_deobf_benchmark.csv"
OUTPUT_DIR = "web/public/benchmark"
DIST_DIR = "web/dist/benchmark"

THEMES = {
    'dark': {
        'bg': '#0f172a',
        'card': '#1e293b',
        'text': '#f8fafc',
        'muted': '#94a3b8',
        'edge': '#334155',
        'grid': '#1e293b',
        'suffix': '_dark',
        'colors': {
            'cyan': '#38bdf8',
            'emerald': '#34d399',
            'purple': '#c084fc',
            'rose': '#fb7185',
            'amber': '#fbbf24',
            'blue': '#60a5fa',
            'indigo': '#818cf8',
            'teal': '#2dd4bf'
        }
    },
    'light': {
        'bg': '#ffffff',
        'card': '#f1f5f9',
        'text': '#0f172a',
        'muted': '#475569',
        'edge': '#cbd5e1',
        'grid': '#e2e8f0',
        'suffix': '_light',
        'colors': {
            'cyan': '#0284c7',
            'emerald': '#059669',
            'purple': '#9333ea',
            'rose': '#e11d48',
            'amber': '#d97706',
            'blue': '#2563eb',
            'indigo': '#4f46e5',
            'teal': '#0d9488'
        }
    }
}


def load_benchmark_data(csv_path):
    rows = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            b_to = r.get('base_timed_out', 'false').lower() == 'true'
            m_to = r.get('max_timed_out', 'false').lower() == 'true'
            rows.append({
                'algo': r['algo'],
                'category': r['category'],
                'base_size': int(r['base_size']),
                'max_size': int(r['max_size']),
                'size_ratio': float(r['size_ratio']),
                'base_main_bbs': int(r['base_main_bbs']),
                'max_main_bbs': int(r['max_main_bbs']),
                'bb_ratio': float(r['bb_ratio']),
                'base_edges': int(r['base_edges']),
                'max_edges': int(r['max_edges']),
                'edges_ratio': float(r['edges_ratio']),
                'base_cyclomatic': int(r['base_cyclomatic']),
                'max_cyclomatic': int(r['max_cyclomatic']),
                'cyc_ratio': float(r['cyc_ratio']),
                'base_z3_time_s': float(r['base_z3_time_s']),
                'max_z3_time_s': float(r['max_z3_time_s']),
                'z3_slowdown': float(r['z3_slowdown']),
                'base_timed_out': b_to,
                'max_timed_out': m_to,
                'base_status': r.get('base_status', 'TIMEOUT' if b_to else 'OK'),
                'max_status': r.get('max_status', 'TIMEOUT' if m_to else 'OK')
            })
    return rows


def plot_size_expansion_by_category(data, output_dir, theme_cfg):
    """Bar chart of average binary size expansion across 8 cryptographic domains."""
    cat_ratios = {}
    for d in data:
        cat_ratios.setdefault(d['category'], []).append(d['size_ratio'])

    cats = sorted(cat_ratios.keys(), key=lambda c: np.mean(cat_ratios[c]), reverse=True)
    means = [np.mean(cat_ratios[c]) for c in cats]
    mins = [np.min(cat_ratios[c]) for c in cats]
    maxs = [np.max(cat_ratios[c]) for c in cats]
    y_err = [
        [means[i] - mins[i] for i in range(len(cats))],
        [maxs[i] - means[i] for i in range(len(cats))]
    ]

    fig, ax = plt.subplots(figsize=(10, 5.5), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    colors = theme_cfg['colors']
    bar_colors = [colors['cyan'], colors['blue'], colors['indigo'], colors['purple'],
                  colors['emerald'], colors['teal'], colors['amber'], colors['rose']]

    bars = ax.barh(cats, means, xerr=y_err, capsize=4, color=bar_colors[:len(cats)],
                   edgecolor=theme_cfg['edge'], alpha=0.9, height=0.65)

    ax.set_xlabel('Binary Code Size Expansion Multiplier (x)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Binary Code Footprint Expansion by Cryptographic Domain (Min / Mean / Max)',
                 fontsize=14, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.tick_params(colors=theme_cfg['muted'], labelsize=11)
    ax.grid(axis='x', color=theme_cfg['grid'], linestyle='--', alpha=0.6)

    for bar, mean in zip(bars, means):
        ax.text(mean + 1.2, bar.get_y() + bar.get_height() / 2, f'{mean:.1f}x',
                va='center', ha='left', color=theme_cfg['text'], fontweight='bold', fontsize=11)

    ax.set_xlim(0, max(maxs) * 1.08)
    plt.tight_layout()

    out_name = f"size_expansion{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(output_dir, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(output_dir, "size_expansion.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_cfg_complexity_multipliers(data, output_dir, theme_cfg):
    """Grouped bar chart showing Main BB Multiplier vs Total Edge Multiplier by Category."""
    cat_data = {}
    for d in data:
        cat_data.setdefault(d['category'], {'bb': [], 'edge': []})
        cat_data[d['category']]['bb'].append(d['bb_ratio'])
        cat_data[d['category']]['edge'].append(d['edges_ratio'])

    cats = sorted(cat_data.keys(), key=lambda c: np.mean(cat_data[c]['bb']), reverse=True)
    bb_means = [np.mean(cat_data[c]['bb']) for c in cats]
    edge_means = [np.mean(cat_data[c]['edge']) for c in cats]

    x = np.arange(len(cats))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 5.5), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    colors = theme_cfg['colors']
    rects1 = ax.bar(x - width/2, bb_means, width, label='Basic Blocks Multiplier (BB)',
                    color=colors['cyan'], edgecolor=theme_cfg['edge'], alpha=0.9)
    rects2 = ax.bar(x + width/2, edge_means, width, label='CFG State Edges Multiplier (Edge)',
                    color=colors['purple'], edgecolor=theme_cfg['edge'], alpha=0.9)

    ax.set_ylabel('Expansion Multiplier (x)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Control Flow Graph Shredding: Basic Block & State-Transition Expansion',
                 fontsize=14, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(cats, rotation=25, ha='right', fontsize=10, color=theme_cfg['muted'])
    ax.tick_params(colors=theme_cfg['muted'], labelsize=10)
    ax.legend(facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=10)
    ax.grid(axis='y', color=theme_cfg['grid'], linestyle='--', alpha=0.6)

    for r in rects1:
        h = r.get_height()
        ax.annotate(f'{h:.1f}x', xy=(r.get_x() + r.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=colors['cyan'], fontsize=9, fontweight='bold')

    for r in rects2:
        h = r.get_height()
        ax.annotate(f'{h:.1f}x', xy=(r.get_x() + r.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=colors['purple'], fontsize=9, fontweight='bold')

    ax.set_ylim(0, max(max(bb_means), max(edge_means)) * 1.18)
    plt.tight_layout()

    out_name = f"cfg_expansion{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(output_dir, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(output_dir, "cfg_expansion.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_cyclomatic_complexity_scatter(data, output_dir, theme_cfg):
    """Scatter comparison of Cyclomatic Complexity V(G) Baseline vs Ensia Max."""
    base_cyc = [d['base_cyclomatic'] for d in data]
    max_cyc = [d['max_cyclomatic'] for d in data]
    cats = [d['category'] for d in data]

    colors = theme_cfg['colors']
    cat_color_map = {
        'Block Cipher': colors['cyan'],
        'Stream Cipher': colors['blue'],
        'Hash / Digest': colors['emerald'],
        'MAC / Authenticator': colors['teal'],
        'Asymmetric / PKC': colors['purple'],
        'Post-Quantum (PQC)': colors['indigo'],
        'KDF / Password': colors['amber'],
        'Lightweight / AEAD': colors['rose']
    }

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    lim_max = max(max(base_cyc), max(max_cyc)) * 1.05
    ax.plot([0, lim_max], [0, lim_max], linestyle=':', color=theme_cfg['muted'], alpha=0.7, label='Unobfuscated Baseline (y = x)')

    unique_cats = sorted(list(set(cats)))
    for cat in unique_cats:
        cx = [base_cyc[i] for i in range(len(data)) if cats[i] == cat]
        cy = [max_cyc[i] for i in range(len(data)) if cats[i] == cat]
        ax.scatter(cx, cy, label=cat, color=cat_color_map.get(cat, colors['cyan']),
                   s=65, alpha=0.88, edgecolors=theme_cfg['bg'], linewidths=0.9)

    ax.set_xlabel('Baseline Cyclomatic Complexity V(G)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_ylabel('Ensia Max Obfuscated Cyclomatic Complexity V(G)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Cyclomatic Complexity Explosion: Baseline vs Ensia Max Across All 79 Algorithms',
                 fontsize=13, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.tick_params(colors=theme_cfg['muted'], labelsize=10)
    ax.grid(color=theme_cfg['grid'], linestyle='--', alpha=0.6)
    ax.legend(facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=9, loc='upper left')

    plt.tight_layout()
    out_name = f"cyclomatic_complexity{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(output_dir, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(output_dir, "cyclomatic_complexity.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_symbolic_execution_resilience(data, output_dir, theme_cfg):
    """Comparison of Symbolic Execution Outcomes: Solved, Timeout, and Active Solver Trapping."""
    base_solved = sum(1 for d in data if d['base_status'] == 'OK')
    base_timeout = sum(1 for d in data if d['base_status'] == 'TIMEOUT')
    base_trapped = sum(1 for d in data if d['base_status'] == 'TRAPPED')

    max_solved = sum(1 for d in data if d['max_status'] == 'OK')
    max_timeout = sum(1 for d in data if d['max_status'] == 'TIMEOUT')
    max_trapped = sum(1 for d in data if d['max_status'] == 'TRAPPED')

    categories = ['Unobfuscated Baseline', 'Ensia Max Profile']

    fig, ax = plt.subplots(figsize=(9.2, 5), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    y_pos = np.arange(len(categories))
    height = 0.45

    colors = theme_cfg['colors']
    solved_counts = [base_solved, max_solved]
    timeout_counts = [base_timeout, max_timeout]
    trapped_counts = [base_trapped, max_trapped]

    b1 = ax.barh(y_pos, solved_counts, height, label='SMT Path Reached Exit (Solved)',
                 color=colors['emerald'], edgecolor=theme_cfg['edge'], alpha=0.9)
    b2 = ax.barh(y_pos, timeout_counts, height, left=solved_counts, label='State Space Saturation (TIMEOUT)',
                 color=colors['rose'], edgecolor=theme_cfg['edge'], alpha=0.9)
    b3 = ax.barh(y_pos, trapped_counts, height,
                 left=[s + t for s, t in zip(solved_counts, timeout_counts)],
                 label='Anti-Analysis Solver Trap (TRAPPED)',
                 color=colors['purple'], edgecolor=theme_cfg['edge'], alpha=0.9)

    ax.set_xlabel('Number of Evaluated Cryptographic Targets (out of 79)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Angr/Z3 Automated Symbolic Traversal: Path Convergence vs Solver Defeat',
                 fontsize=13, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=11, color=theme_cfg['text'], fontweight='bold')
    ax.tick_params(colors=theme_cfg['muted'], labelsize=10)
    ax.legend(facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=9, loc='lower right')
    ax.grid(axis='x', color=theme_cfg['grid'], linestyle='--', alpha=0.6)

    # Annotations
    ax.text(base_solved / 2, y_pos[0], f'{base_solved} ({base_solved/79*100:.1f}%)',
            ha='center', va='center', color='#ffffff', fontweight='bold', fontsize=10)
    if base_timeout > 0:
        ax.text(base_solved + base_timeout / 2, y_pos[0], f'{base_timeout}',
                ha='center', va='center', color='#ffffff', fontweight='bold', fontsize=10)

    ax.text(max_solved / 2, y_pos[1], f'{max_solved}',
            ha='center', va='center', color='#ffffff', fontweight='bold', fontsize=10)
    ax.text(max_solved + max_timeout / 2, y_pos[1], f'{max_timeout} TO',
            ha='center', va='center', color='#ffffff', fontweight='bold', fontsize=10)
    ax.text(max_solved + max_timeout + max_trapped / 2, y_pos[1], f'{max_trapped} Trap',
            ha='center', va='center', color='#ffffff', fontweight='bold', fontsize=10)

    ax.set_xlim(0, 85)
    plt.tight_layout()

    out_name = f"symbolic_execution_resilience{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(output_dir, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(output_dir, "symbolic_execution_resilience.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_category_radar(data, output_dir, theme_cfg):
    """Radar chart comparing multi-dimensional protection metrics across domains."""
    cat_metrics = {}
    for d in data:
        cat_metrics.setdefault(d['category'], {'size': [], 'bb': [], 'edges': [], 'cyc': [], 'defeated': []})
        cat_metrics[d['category']]['size'].append(d['size_ratio'])
        cat_metrics[d['category']]['bb'].append(d['bb_ratio'])
        cat_metrics[d['category']]['edges'].append(d['edges_ratio'])
        cat_metrics[d['category']]['cyc'].append(d['cyc_ratio'])
        cat_metrics[d['category']]['defeated'].append(1.0 if d['max_status'] in ['TIMEOUT', 'TRAPPED'] else 0.0)

    categories = list(cat_metrics.keys())
    labels = ['Size Expansion', 'BB Multiplier', 'CFG Edges', 'Cyclomatic V(G)', 'SMT Defeat Rate']
    num_vars = len(labels)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    colors = theme_cfg['colors']
    selected_cats = ['Block Cipher', 'Hash / Digest', 'Asymmetric / PKC', 'Stream Cipher']
    cat_colors = [colors['cyan'], colors['emerald'], colors['purple'], colors['amber']]

    for cat, color in zip(selected_cats, cat_colors):
        m = cat_metrics[cat]
        raw_vals = [
            min(100, np.mean(m['size']) / 55 * 100),
            min(100, np.mean(m['bb']) / 40 * 100),
            min(100, np.mean(m['edges']) / 30 * 100),
            min(100, np.mean(m['cyc']) / 15 * 100),
            np.mean(m['defeated']) * 100
        ]
        vals = raw_vals + raw_vals[:1]
        ax.plot(angles, vals, color=color, linewidth=2.2, label=f"{cat}")
        ax.fill(angles, vals, color=color, alpha=0.15)

    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_thetagrids(np.degrees(angles[:-1]), labels, color=theme_cfg['text'], fontsize=11, fontweight='bold')
    ax.tick_params(colors=theme_cfg['muted'])
    ax.grid(color=theme_cfg['grid'], linestyle='--', alpha=0.7)
    ax.set_ylim(0, 105)
    ax.set_yticklabels([])

    ax.set_title('Multi-Dimensional Reverse-Engineering Resistance Profile',
                 fontsize=14, fontweight='bold', color=theme_cfg['text'], pad=25)
    ax.legend(facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=10,
              loc='upper right', bbox_to_anchor=(1.25, 1.05))

    plt.tight_layout()
    out_name = f"category_radar{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(output_dir, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(output_dir, "category_radar.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DIST_DIR, exist_ok=True)
    if not os.path.exists(CSV_PATH):
        print(f"[!] Error: CSV not found at {CSV_PATH}")
        return

    data = load_benchmark_data(CSV_PATH)
    print(f"[*] Loaded {len(data)} target records from {CSV_PATH}")

    for theme_name, theme_cfg in THEMES.items():
        print(f"\n[+] Generating {theme_name.upper()} theme charts...")
        plot_size_expansion_by_category(data, OUTPUT_DIR, theme_cfg)
        plot_cfg_complexity_multipliers(data, OUTPUT_DIR, theme_cfg)
        plot_cyclomatic_complexity_scatter(data, OUTPUT_DIR, theme_cfg)
        plot_symbolic_execution_resilience(data, OUTPUT_DIR, theme_cfg)
        plot_category_radar(data, OUTPUT_DIR, theme_cfg)

    # Sync to dist/
    for fname in os.listdir(OUTPUT_DIR):
        if fname.endswith('.svg'):
            shutil.copy2(os.path.join(OUTPUT_DIR, fname), os.path.join(DIST_DIR, fname))
    print("\n[+] All benchmark charts generated & synced to public/ and dist/.")


if __name__ == '__main__':
    main()
