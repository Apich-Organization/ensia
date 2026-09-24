#!/usr/bin/env python3
"""
generate_additional_charts.py
Generates SVG charts for:
1. barrier_protection_gap.svg (Per-Pass Retention: Respecting vs Stripped Barriers under opt -O3)
2. symbolic_crackme_resilience.svg (Angr 9.3 + Z3 4.12 SMT Exploration & Solving Time)
With Dual-Theme (Dark & Light) support.
"""

import os
import shutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = "web/public/benchmark"
DIST_DIR = "web/dist/benchmark"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(DIST_DIR, exist_ok=True)

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


def plot_barrier_protection_gap(theme_cfg):
    passes = [
        "MBA (MBAOBF)",
        "Vector (VOBF)",
        "Bogus CF (BCF)",
        "Subst (SUB)",
        "Const Enc (CONST)",
        "Block Split (SPLIT)",
        "AntiClassDump (ACD)",
        "Flattening (CFF)",
        "Chaos SM (CSM)"
    ]
    respect = [84.0, 76.0, 68.8, 89.1, 76.9, 52.4, 46.9, 29.0, 29.0]
    stripped = [32.8, 27.0, 22.9, 48.7, 48.1, 28.7, 30.0, 29.0, 29.0]
    gaps = [r - s for r, s in zip(respect, stripped)]

    x = np.arange(len(passes))
    width = 0.38

    fig, ax = plt.subplots(figsize=(12, 6.2), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    colors = theme_cfg['colors']
    rects1 = ax.bar(x - width/2, respect, width, label='Barrier-Respecting Retention (opt -O3)',
                    color=colors['emerald'], edgecolor=theme_cfg['edge'], alpha=0.9)
    rects2 = ax.bar(x + width/2, stripped, width, label='Barrier-Stripped Retention (Adversarial opt -O3)',
                    color=colors['rose'], edgecolor=theme_cfg['edge'], alpha=0.9)

    ax.set_ylabel('IR Instruction Retention (%)', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Adversarial Compiler Stripping Resilience: Barrier Protection Gap Under opt -O3',
                 fontsize=14, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(passes, rotation=22, ha='right', fontsize=10, color=theme_cfg['muted'])
    ax.tick_params(colors=theme_cfg['muted'], labelsize=10)
    ax.legend(facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=10.5, loc='upper right')
    ax.grid(axis='y', color=theme_cfg['grid'], linestyle='--', alpha=0.6)

    for i, (r1, r2, gap) in enumerate(zip(rects1, rects2, gaps)):
        h1 = r1.get_height()
        h2 = r2.get_height()
        ax.annotate(f'{h1:.1f}%', xy=(r1.get_x() + r1.get_width() / 2, h1),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=colors['emerald'], fontsize=8.5, fontweight='bold')
        ax.annotate(f'{h2:.1f}%', xy=(r2.get_x() + r2.get_width() / 2, h2),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom',
                    color=colors['rose'], fontsize=8.5, fontweight='bold')
        if gap > 5.0:
            top = max(h1, h2)
            ax.annotate(f'Gap: +{gap:.1f}%', xy=(r1.get_x() + width, top + 7),
                        ha='center', va='bottom', color=colors['amber'], fontsize=8.5,
                        fontweight='bold', bbox=dict(boxstyle='round,pad=0.2', facecolor=theme_cfg['card'], edgecolor=colors['amber'], alpha=0.85))

    ax.set_ylim(0, 108)
    plt.tight_layout()

    out_name = f"barrier_protection_gap{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(OUTPUT_DIR, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(OUTPUT_DIR, "barrier_protection_gap.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def plot_symbolic_crackme_resilience(theme_cfg):
    targets = [
        "Baseline",
        "SUBOBF",
        "VOBF",
        "BCFOBF",
        "CFFOBF",
        "MBAOBF",
        "CSMOBF",
        "CONSTENC",
        "Preset Low",
        "Preset Mid",
        "Preset High",
        "Preset Max"
    ]
    # Times in seconds for constructor-aware angr
    times = [0.88, 0.73, 0.47, 0.63, 1.05, 1.80, 2.24, 0.62, 4.29, 4.62, 4.48, 60.0]
    # Standard angr status: True if trapped/exhausted, False if solved
    trapped_standard = [False, False, False, False, False, False, False, True, True, True, True, True]
    is_timeout = [False, False, False, False, False, False, False, False, False, False, False, True]

    y_pos = np.arange(len(targets))

    fig, ax = plt.subplots(figsize=(12, 6.5), facecolor=theme_cfg['bg'])
    ax.set_facecolor(theme_cfg['bg'])

    colors = theme_cfg['colors']
    bar_colors = []
    for timeout, trapped in zip(is_timeout, trapped_standard):
        if timeout:
            bar_colors.append(colors['rose'])
        elif trapped:
            bar_colors.append(colors['purple'])
        else:
            bar_colors.append(colors['cyan'])

    bars = ax.barh(y_pos, times, color=bar_colors, edgecolor=theme_cfg['edge'], height=0.65, alpha=0.9)

    ax.set_xlabel('Symbolic Execution Solving Time (Seconds) [Angr 9.3 + Z3 4.12]', fontsize=12, color=theme_cfg['text'], labelpad=10)
    ax.set_title('Real-World Crackme Symbolic Execution Defense: Solving Latency & Solver Trapping',
                 fontsize=14, fontweight='bold', color=theme_cfg['text'], pad=15)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(targets, fontsize=10.5, color=theme_cfg['muted'])
    ax.tick_params(colors=theme_cfg['muted'], labelsize=10.5)
    ax.grid(axis='x', color=theme_cfg['grid'], linestyle='--', alpha=0.6)

    for i, (bar, t, trapped, timeout) in enumerate(zip(bars, times, trapped_standard, is_timeout)):
        w = bar.get_width()
        y = bar.get_y() + bar.get_height() / 2
        if timeout:
            label = "TIMEOUT (>60.0s, 850+ states, Trapped)"
            ax.text(w + 1.0, y, label, va='center', ha='left', color=colors['rose'], fontweight='bold', fontsize=9.5)
        elif trapped:
            label = f"{t:.2f}s (Trap: Standard Angr EXHAUSTED)"
            ax.text(w + 1.0, y, label, va='center', ha='left', color=colors['purple'], fontweight='bold', fontsize=9.5)
        else:
            label = f"{t:.2f}s (Solved)"
            ax.text(w + 1.0, y, label, va='center', ha='left', color=colors['cyan'], fontweight='bold', fontsize=9.5)

    ax.set_xlim(0, 75)

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=colors['cyan'], edgecolor=theme_cfg['edge'], label='Single Pass (Solved directly in <2.5s)'),
        Patch(facecolor=colors['purple'], edgecolor=theme_cfg['edge'], label='Constructor-Bypass Trap (Defeats standard angr; 5x slowdown)'),
        Patch(facecolor=colors['rose'], edgecolor=theme_cfg['edge'], label='Preset Max (State Space Explosion & Solver Timeout >60s)')
    ]
    ax.legend(handles=legend_elements, facecolor=theme_cfg['card'], edgecolor=theme_cfg['edge'], labelcolor=theme_cfg['text'], fontsize=10, loc='lower right')

    plt.tight_layout()
    out_name = f"symbolic_crackme_resilience{theme_cfg['suffix']}.svg"
    svg_path = os.path.join(OUTPUT_DIR, out_name)
    plt.savefig(svg_path, format='svg', bbox_inches='tight', transparent=False)
    if theme_cfg['suffix'] == '_dark':
        plt.savefig(os.path.join(OUTPUT_DIR, "symbolic_crackme_resilience.svg"), format='svg', bbox_inches='tight', transparent=False)
    plt.close()
    print(f"[+] Saved: {svg_path}")


def main():
    for theme_name, theme_cfg in THEMES.items():
        print(f"\n[+] Generating additional {theme_name.upper()} theme charts...")
        plot_barrier_protection_gap(theme_cfg)
        plot_symbolic_crackme_resilience(theme_cfg)

    # Sync to dist/
    for fname in os.listdir(OUTPUT_DIR):
        if fname.endswith('.svg'):
            shutil.copy2(os.path.join(OUTPUT_DIR, fname), os.path.join(DIST_DIR, fname))
    print("\n[+] All additional charts generated & synced.")


if __name__ == '__main__':
    main()
