#!/usr/bin/env python3
"""
generate_benchmark_charts.py
====================================================================================
Generates SVG and PNG benchmark charts for Ensia's web dashboard from full_deobf_benchmark.csv
====================================================================================
"""

import csv
import os
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

CSV_PATH = "benchmark/results/full_deobf_benchmark.csv"
OUTPUT_DIR = "web/public/benchmark"

plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Helvetica', 'Arial', 'sans-serif']
plt.rcParams['axes.edgecolor'] = '#334155'
plt.rcParams['axes.linewidth'] = 1.0
plt.rcParams['grid.color'] = '#1e293b'
plt.rcParams['grid.linestyle'] = '--'
plt.rcParams['grid.alpha'] = 0.7

DARK_BG = '#0f172a'
CARD_BG = '#1e293b'
TEXT_COLOR = '#f8fafc'
TEXT_MUTED = '#94a3b8'

COLORS = {
    'cyan': '#38bdf8',
    'emerald': '#34d399',
    'purple': '#c084fc',
    'rose': '#fb7185',
    'amber': '#fbbf24',
    'blue': '#60a5fa',
    'indigo': '#818cf8',
    'teal': '#2dd4bf'
}


def load_benchmark_data(csv_path):
    rows = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
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
                'base_timed_out': r['base_timed_out'].lower() == 'true',
                'max_timed_out': r['max_timed_out'].lower() == 'true'
            })
    return rows


def plot_size_expansion_by_category(data, output_dir):
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

    fig, ax = plt.subplots(figsize=(10, 5.5), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)

    bar_colors = [COLORS['cyan'], COLORS['blue'], COLORS['indigo'], COLORS['purple'],
                  COLORS['emerald'], COLORS['teal'], COLORS['amber'], COLORS['rose']]

    bars = ax.barh(cats, means, xerr=y_err, capsize=4, color=bar_colors[:len(cats)],
                   edgecolor='#475569', alpha=0.9, height=0.65)

    ax.set_xlabel('Binary Code Size Expansion Multiplier (x)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Binary Code Footprint Expansion by Cryptographic Domain (Min / Mean / Max)',
                 fontsize=14, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.tick_params(colors=TEXT_MUTED, labelsize=11)
    ax.grid(axis='x', color='#334155', linestyle='--', alpha=0.5)

    for bar, mean in zip(bars, means):
        ax.text(mean + 0.8, bar.get_y() + bar.get_height() / 2, f'{mean:.1f}x',
                va='center', ha='left', color=TEXT_COLOR, fontweight='bold', fontsize=11)

    ax.set_xlim(0, max(maxs) * 1.08)
    plt.tight_layout()
    svg_path = os.path.join(output_dir, 'size_expansion.svg')
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_cfg_complexity_multipliers(data, output_dir):
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

    fig, ax = plt.subplots(figsize=(11, 5.5), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)

    rects1 = ax.bar(x - width/2, bb_means, width, label='Basic Blocks Multiplier (BB)',
                    color=COLORS['cyan'], edgecolor='#475569', alpha=0.9)
    rects2 = ax.bar(x + width/2, edge_means, width, label='CFG State Edges Multiplier (Edge)',
                    color=COLORS['purple'], edgecolor='#475569', alpha=0.9)

    ax.set_ylabel('Expansion Multiplier (x)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Control Flow Graph Shredding: Basic Block & State-Transition Expansion',
                 fontsize=14, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(cats, rotation=25, ha='right', fontsize=10, color=TEXT_MUTED)
    ax.tick_params(colors=TEXT_MUTED, labelsize=10)
    ax.legend(facecolor=CARD_BG, edgecolor='#475569', labelcolor=TEXT_COLOR, fontsize=10)
    ax.grid(axis='y', color='#334155', linestyle='--', alpha=0.5)

    for r in rects1:
        h = r.get_height()
        ax.annotate(f'{h:.1f}x', xy=(r.get_x() + r.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=COLORS['cyan'], fontsize=9, fontweight='bold')

    for r in rects2:
        h = r.get_height()
        ax.annotate(f'{h:.1f}x', xy=(r.get_x() + r.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=COLORS['purple'], fontsize=9, fontweight='bold')

    ax.set_ylim(0, max(max(bb_means), max(edge_means)) * 1.18)
    plt.tight_layout()
    svg_path = os.path.join(output_dir, 'cfg_expansion.svg')
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_cyclomatic_complexity_scatter(data, output_dir):
    """Scatter comparison of Cyclomatic Complexity V(G) Baseline vs Ensia Max."""
    base_cyc = [d['base_cyclomatic'] for d in data]
    max_cyc = [d['max_cyclomatic'] for d in data]
    cats = [d['category'] for d in data]

    cat_color_map = {
        'Block Cipher': COLORS['cyan'],
        'Stream Cipher': COLORS['blue'],
        'Hash / Digest': COLORS['emerald'],
        'MAC / Authenticator': COLORS['teal'],
        'Asymmetric / PKC': COLORS['purple'],
        'Post-Quantum (PQC)': COLORS['indigo'],
        'KDF / Password': COLORS['amber'],
        'Lightweight / AEAD': COLORS['rose']
    }

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)

    # Plot diagonal reference (y = x)
    lim_max = max(max(base_cyc), max(max_cyc)) * 1.05
    ax.plot([0, lim_max], [0, lim_max], linestyle=':', color='#64748b', alpha=0.6, label='Unobfuscated Baseline (y = x)')

    # Group by category for legend
    unique_cats = sorted(list(set(cats)))
    for cat in unique_cats:
        cx = [base_cyc[i] for i in range(len(data)) if cats[i] == cat]
        cy = [max_cyc[i] for i in range(len(data)) if cats[i] == cat]
        ax.scatter(cx, cy, label=cat, color=cat_color_map.get(cat, COLORS['cyan']),
                   s=60, alpha=0.85, edgecolors='#0f172a', linewidths=0.8)

    ax.set_xlabel('Baseline Cyclomatic Complexity V(G)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_ylabel('Ensia Max Obfuscated Cyclomatic Complexity V(G)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Cyclomatic Complexity Explosion: Baseline vs Ensia Max Across All 79 Algorithms',
                 fontsize=13, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.tick_params(colors=TEXT_MUTED, labelsize=10)
    ax.grid(color='#334155', linestyle='--', alpha=0.5)
    ax.legend(facecolor=CARD_BG, edgecolor='#475569', labelcolor=TEXT_COLOR, fontsize=9, loc='upper left')

    plt.tight_layout()
    svg_path = os.path.join(output_dir, 'cyclomatic_complexity.svg')
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_symbolic_execution_resilience(data, output_dir):
    """Comparison of Symbolic Execution Completion vs Timeout on Baseline vs Ensia Max."""
    base_success = sum(1 for d in data if not d['base_timed_out'])
    base_timeout = sum(1 for d in data if d['base_timed_out'])

    max_success = sum(1 for d in data if not d['max_timed_out'])
    max_timeout = sum(1 for d in data if d['max_timed_out'])

    categories = ['Unobfuscated Baseline', 'Ensia Max Profile']
    solved_counts = [base_success, max_success]
    timeout_counts = [base_timeout, max_timeout]

    fig, ax = plt.subplots(figsize=(8.5, 5), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)

    y_pos = np.arange(len(categories))
    height = 0.45

    b1 = ax.barh(y_pos, solved_counts, height, label='SMT Reached Exit (Solved)', color=COLORS['emerald'],
                 edgecolor='#475569', alpha=0.9)
    b2 = ax.barh(y_pos, timeout_counts, height, left=solved_counts, label='Symbolic Path Explosion (TIMEOUT)',
                 color=COLORS['rose'], edgecolor='#475569', alpha=0.9)

    ax.set_xlabel('Number of Evaluated Cryptographic Targets (out of 79)', fontsize=12, color=TEXT_COLOR, labelpad=10)
    ax.set_title('Angr/Z3 Automated Symbolic Traversal: Path Convergence vs Solver Trapping',
                 fontsize=13, fontweight='bold', color=TEXT_COLOR, pad=15)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=11, color=TEXT_COLOR, fontweight='bold')
    ax.tick_params(colors=TEXT_MUTED, labelsize=10)
    ax.legend(facecolor=CARD_BG, edgecolor='#475569', labelcolor=TEXT_COLOR, fontsize=10, loc='lower right')
    ax.grid(axis='x', color='#334155', linestyle='--', alpha=0.5)

    # Annotations
    ax.text(base_success / 2, y_pos[0], f'{base_success} ({base_success/79*100:.1f}%)',
            ha='center', va='center', color='#0f172a', fontweight='bold', fontsize=11)
    ax.text(base_success + base_timeout / 2, y_pos[0], f'{base_timeout} ({base_timeout/79*100:.1f}%)',
            ha='center', va='center', color=TEXT_COLOR, fontweight='bold', fontsize=11)

    ax.text(max_success + max_timeout / 2, y_pos[1], f'{max_timeout} / 79 ({max_timeout/79*100:.1f}% TIMEOUT)',
            ha='center', va='center', color=TEXT_COLOR, fontweight='bold', fontsize=11)

    ax.set_xlim(0, 85)
    plt.tight_layout()
    svg_path = os.path.join(output_dir, 'symbolic_execution_resilience.svg')
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_category_radar(data, output_dir):
    """Radar chart comparing multi-dimensional protection metrics across domains."""
    cat_metrics = {}
    for d in data:
        cat_metrics.setdefault(d['category'], {'size': [], 'bb': [], 'edges': [], 'cyc': [], 'timeout': []})
        cat_metrics[d['category']]['size'].append(d['size_ratio'])
        cat_metrics[d['category']]['bb'].append(d['bb_ratio'])
        cat_metrics[d['category']]['edges'].append(d['edges_ratio'])
        cat_metrics[d['category']]['cyc'].append(d['cyc_ratio'])
        cat_metrics[d['category']]['timeout'].append(1.0 if d['max_timed_out'] else 0.0)

    categories = list(cat_metrics.keys())
    labels = ['Size Expansion', 'BB Multiplier', 'CFG Edges', 'Cyclomatic V(G)', 'SMT Trapping']
    num_vars = len(labels)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True), facecolor=DARK_BG)
    ax.set_facecolor(DARK_BG)

    # Normalize metrics to 0-100 scale for visual comparability
    selected_cats = ['Block Cipher', 'Hash / Digest', 'Asymmetric / PKC', 'Stream Cipher']
    cat_colors = [COLORS['cyan'], COLORS['emerald'], COLORS['purple'], COLORS['amber']]

    for cat, color in zip(selected_cats, cat_colors):
        m = cat_metrics[cat]
        # Normalize relative to macro maximums
        raw_vals = [
            min(100, np.mean(m['size']) / 25 * 100),
            min(100, np.mean(m['bb']) / 15 * 100),
            min(100, np.mean(m['edges']) / 15 * 100),
            min(100, np.mean(m['cyc']) / 12 * 100),
            np.mean(m['timeout']) * 100
        ]
        vals = raw_vals + raw_vals[:1]
        ax.plot(angles, vals, color=color, linewidth=2, label=f"{cat}")
        ax.fill(angles, vals, color=color, alpha=0.15)

    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_thetagrids(np.degrees(angles[:-1]), labels, color=TEXT_COLOR, fontsize=11, fontweight='bold')
    ax.tick_params(colors=TEXT_MUTED)
    ax.grid(color='#334155', linestyle='--', alpha=0.6)
    ax.set_ylim(0, 105)
    ax.set_yticklabels([])

    ax.set_title('Multi-Dimensional Reverse-Engineering Resistance Profile',
                 fontsize=14, fontweight='bold', color=TEXT_COLOR, pad=25)
    ax.legend(facecolor=CARD_BG, edgecolor='#475569', labelcolor=TEXT_COLOR, fontsize=10,
              loc='upper right', bbox_to_anchor=(1.25, 1.05))

    plt.tight_layout()
    svg_path = os.path.join(output_dir, 'category_radar.svg')
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not os.path.exists(CSV_PATH):
        print(f"[!] Error: CSV not found at {CSV_PATH}")
        return

    data = load_benchmark_data(CSV_PATH)
    print(f"[*] Loaded {len(data)} target records from {CSV_PATH}")

    plot_size_expansion_by_category(data, OUTPUT_DIR)
    plot_cfg_complexity_multipliers(data, OUTPUT_DIR)
    plot_cyclomatic_complexity_scatter(data, OUTPUT_DIR)
    plot_symbolic_execution_resilience(data, OUTPUT_DIR)
    plot_category_radar(data, OUTPUT_DIR)
    print("[+] All benchmark charts generated successfully.")


if __name__ == '__main__':
    main()
