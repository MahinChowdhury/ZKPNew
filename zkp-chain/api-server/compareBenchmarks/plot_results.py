#!/usr/bin/env python3
"""
plot_results.py — Publication-Quality Figures for Q1 Journal Paper
==================================================================

Reads benchmark_results.json and generates:
  • Figure 1: R1CS Constraints & Proof Generation Time (grouped bar)
  • Figure 2: Storage / Payload Comparison (grouped bar)
  • Figure 3: Computational Latency Breakdown (stacked bar + error bars)
  • Figure 4: On-Chain Gas Cost Breakdown (stacked bar)
  • Table 1 & Table 2 as LaTeX-ready console output

Usage:
  python3 plot_results.py                    # default: reads benchmark_results.json
  python3 plot_results.py --input results.json --dpi 600
  python3 plot_results.py --format pdf       # export as PDF instead of PNG

Requirements:
  pip install matplotlib numpy
"""

import json
import argparse
import os
import sys
import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend for server/WSL
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    from matplotlib.patches import FancyBboxPatch
except ImportError:
    print("ERROR: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)

# ============================================================
# Config
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(SCRIPT_DIR, "benchmark_results.json")

# Color palette — modern, publication-friendly
FACE_COLOR = "#E74C3C"       # Rich red
FACE_COLOR_LIGHT = "#F1948A"  # Light red
IRIS_COLOR = "#2E86C1"       # Deep blue
IRIS_COLOR_LIGHT = "#85C1E9"  # Light blue
ACCENT_GOLD = "#F39C12"
ACCENT_GREEN = "#27AE60"
BG_COLOR = "#FAFAFA"
GRID_COLOR = "#E0E0E0"
TEXT_COLOR = "#2C3E50"

# Hatching for print-friendly (B&W) distinction
FACE_HATCH = "///"
IRIS_HATCH = "..."


def load_data(filepath):
    """Load benchmark results from JSON."""
    with open(filepath, "r") as f:
        data = json.load(f)
    print(f"✅ Loaded benchmark data from: {filepath}")
    print(f"   Timestamp: {data['metadata']['timestamp']}")
    print(f"   Platform:  {data['metadata']['platform']}")
    print(f"   CPU:       {data['metadata']['cpu']}")
    print(f"   Runs:      {data['metadata']['num_runs']}")
    print(f"   Prover:    {data['metadata']['prover']}")
    return data


def setup_style():
    """Configure matplotlib for publication-quality output."""
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif", "serif"],
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "figure.titlesize": 14,
        "axes.linewidth": 0.8,
        "grid.linewidth": 0.5,
        "lines.linewidth": 1.5,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.15,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "axes.facecolor": BG_COLOR,
        "figure.facecolor": "white",
        "axes.edgecolor": "#CCCCCC",
    })


def add_value_labels(ax, bars, fmt="{:.0f}", fontsize=9, offset=0.02):
    """Add value labels on top of bars."""
    ymax = ax.get_ylim()[1]
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + ymax * offset,
                fmt.format(height),
                ha="center", va="bottom",
                fontsize=fontsize, fontweight="bold",
                color=TEXT_COLOR,
            )


# ============================================================
# Figure 1: R1CS Constraints & Proof Time (THE key figure)
# ============================================================
def plot_figure1(data, output_dir, fmt):
    """
    Figure 1: Side-by-side grouped bar chart
    Left axis: R1CS Constraints
    Right axis: Total Prover Time (ms)
    """
    fig, ax1 = plt.subplots(figsize=(8, 5))

    labels = ["Face\n(Cosine Similarity)", "Iris\n(Hamming Distance)"]
    x = np.arange(len(labels))
    width = 0.30

    constraints = data["figure1_constraints_and_time"]["r1cs_constraints"]
    total_prover = data["figure1_constraints_and_time"]["total_prover_ms"]

    # Left axis: Constraints
    bars1 = ax1.bar(
        x - width / 2, constraints, width,
        label="R1CS Constraints",
        color=[FACE_COLOR, IRIS_COLOR],
        edgecolor="white", linewidth=1.2,
        zorder=3, alpha=0.9,
    )
    ax1.set_ylabel("R1CS Constraints", color=TEXT_COLOR, fontweight="bold")
    ax1.set_xlabel("")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontweight="bold")
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v / 1000:.0f}K"))
    ax1.tick_params(axis="y", colors=TEXT_COLOR)
    ax1.set_ylim(0, max(constraints) * 1.25)

    # Add constraint labels
    for bar, val in zip(bars1, constraints):
        ax1.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + max(constraints) * 0.02,
            f"{val:,}",
            ha="center", va="bottom",
            fontsize=10, fontweight="bold", color=TEXT_COLOR,
        )

    # Right axis: Prover time
    ax2 = ax1.twinx()
    bars2 = ax2.bar(
        x + width / 2, total_prover, width,
        label="Total Prover Time",
        color=[FACE_COLOR_LIGHT, IRIS_COLOR_LIGHT],
        edgecolor="white", linewidth=1.2,
        hatch="///",
        zorder=3, alpha=0.85,
    )
    ax2.set_ylabel("Total Prover Time (ms)", color=TEXT_COLOR, fontweight="bold")
    ax2.tick_params(axis="y", colors=TEXT_COLOR)
    ax2.set_ylim(0, max(total_prover) * 1.35)

    # Add time labels
    for bar, val in zip(bars2, total_prover):
        label = f"{val:.0f} ms" if val < 1000 else f"{val / 1000:.2f} s"
        ax2.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + max(total_prover) * 0.02,
            label,
            ha="center", va="bottom",
            fontsize=10, fontweight="bold", color=TEXT_COLOR,
        )

    # Speedup annotation
    ratio = constraints[0] / constraints[1] if constraints[1] > 0 else 0
    time_ratio = total_prover[0] / total_prover[1] if total_prover[1] > 0 else 0
    ax1.text(
        0.5, 0.95,
        f"Constraint reduction: {ratio:.1f}×  |  Speedup: {time_ratio:.1f}×",
        transform=ax1.transAxes,
        ha="center", va="top",
        fontsize=11, fontweight="bold",
        color="white",
        bbox=dict(boxstyle="round,pad=0.4", facecolor=ACCENT_GREEN, alpha=0.9, edgecolor="none"),
    )

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=FACE_COLOR, alpha=0.9, label="R1CS Constraints"),
        Patch(facecolor=FACE_COLOR_LIGHT, hatch="///", alpha=0.85, label="Total Prover Time"),
    ]
    ax1.legend(handles=legend_elements, loc="upper left", framealpha=0.9)

    ax1.set_title(
        "Figure 1: Circuit Complexity vs. Proving Time",
        fontweight="bold", pad=15,
    )

    plt.tight_layout()
    outpath = os.path.join(output_dir, f"figure1_constraints_vs_time.{fmt}")
    fig.savefig(outpath, dpi=300, facecolor="white")
    plt.close(fig)
    print(f"  📊 Saved: {outpath}")


# ============================================================
# Figure 2: Storage / Payload Comparison
# ============================================================
def plot_figure2(data, output_dir, fmt):
    """
    Figure 2: Grouped bar chart of storage sizes
    Proving key, WASM, Verification key, Proof payload
    """
    fig, ax = plt.subplots(figsize=(9, 5))

    storage = data["figure2_storage"]
    categories = ["Proving Key\n(.zkey)", "WASM Witness\nGenerator", "R1CS\nConstraints", "Verification\nKey", "Proof\nPayload"]

    face_vals_bytes = [
        storage["zkey_bytes"][0],
        storage["wasm_bytes"][0],
        storage["r1cs_bytes"][0],
        storage["vkey_bytes"][0],
        storage["proof_bytes"][0],
    ]
    iris_vals_bytes = [
        storage["zkey_bytes"][1],
        storage["wasm_bytes"][1],
        storage["r1cs_bytes"][1],
        storage["vkey_bytes"][1],
        storage["proof_bytes"][1],
    ]

    # Convert to MB for readability (except proof which is in KB)
    face_vals_mb = [v / (1024 * 1024) for v in face_vals_bytes]
    iris_vals_mb = [v / (1024 * 1024) for v in iris_vals_bytes]

    x = np.arange(len(categories))
    width = 0.32

    bars1 = ax.bar(
        x - width / 2, face_vals_mb, width,
        label="Face (Cosine)",
        color=FACE_COLOR, edgecolor="white", linewidth=1,
        alpha=0.9, zorder=3,
    )
    bars2 = ax.bar(
        x + width / 2, iris_vals_mb, width,
        label="Iris (Hamming)",
        color=IRIS_COLOR, edgecolor="white", linewidth=1,
        alpha=0.9, zorder=3,
    )

    def fmt_size(mb):
        if mb < 0.001:
            return f"{mb * 1024 * 1024:.0f} B"
        if mb < 1:
            return f"{mb * 1024:.1f} KB"
        return f"{mb:.2f} MB"

    # Value labels
    ymax = max(max(face_vals_mb), max(iris_vals_mb))
    for bar, val in zip(bars1, face_vals_mb):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + ymax * 0.015,
            fmt_size(val), ha="center", va="bottom",
            fontsize=8, fontweight="bold", color=FACE_COLOR, rotation=0,
        )
    for bar, val in zip(bars2, iris_vals_mb):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + ymax * 0.015,
            fmt_size(val), ha="center", va="bottom",
            fontsize=8, fontweight="bold", color=IRIS_COLOR, rotation=0,
        )

    # Ratio annotations on zkey
    zkey_ratio = face_vals_bytes[0] / iris_vals_bytes[0] if iris_vals_bytes[0] > 0 else 0
    ax.annotate(
        f"{zkey_ratio:.1f}× smaller",
        xy=(0 + width / 2, iris_vals_mb[0]),
        xytext=(0.8, max(face_vals_mb) * 0.75),
        fontsize=10, fontweight="bold", color=ACCENT_GREEN,
        arrowprops=dict(arrowstyle="->", color=ACCENT_GREEN, lw=1.5),
        ha="center",
    )

    ax.set_ylabel("Size (MB)", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontweight="bold")
    ax.legend(loc="upper right", framealpha=0.9)
    ax.set_ylim(0, ymax * 1.20)
    ax.set_title(
        "Figure 2: Storage & Payload Size Comparison",
        fontweight="bold", pad=15,
    )

    plt.tight_layout()
    outpath = os.path.join(output_dir, f"figure2_storage_comparison.{fmt}")
    fig.savefig(outpath, dpi=300, facecolor="white")
    plt.close(fig)
    print(f"  📊 Saved: {outpath}")


# ============================================================
# Figure 3: Latency Breakdown (stacked with error bars)
# ============================================================
def plot_figure3(data, output_dir, fmt):
    """
    Figure 3: Stacked bar chart of witness gen + proof gen + verify
    with per-run error bars from raw_runs
    """
    fig, ax = plt.subplots(figsize=(7, 5.5))

    labels = ["Face\n(Cosine Similarity)", "Iris\n(Hamming Distance)"]
    x = np.arange(len(labels))
    width = 0.45

    fig1 = data["figure1_constraints_and_time"]
    raw = data["raw_runs"]

    witness = fig1["witness_gen_ms"]
    proof = fig1["proof_gen_ms"]
    verify = fig1["proof_verify_ms"]

    # Compute std for error bars
    face_witness_std = np.std(raw["face"]["witness_gen_ms"]) if len(raw["face"]["witness_gen_ms"]) > 1 else 0
    face_proof_std = np.std(raw["face"]["proof_gen_ms"]) if len(raw["face"]["proof_gen_ms"]) > 1 else 0
    iris_witness_std = np.std(raw["iris"]["witness_gen_ms"]) if len(raw["iris"]["witness_gen_ms"]) > 1 else 0
    iris_proof_std = np.std(raw["iris"]["proof_gen_ms"]) if len(raw["iris"]["proof_gen_ms"]) > 1 else 0

    # Stacked bars
    b1 = ax.bar(x, witness, width,
                label="Witness Generation",
                color=[FACE_COLOR, IRIS_COLOR],
                edgecolor="white", linewidth=1, alpha=0.9, zorder=3)

    b2 = ax.bar(x, proof, width, bottom=witness,
                label="Proof Generation (Groth16)",
                color=[FACE_COLOR_LIGHT, IRIS_COLOR_LIGHT],
                edgecolor="white", linewidth=1, alpha=0.85, zorder=3,
                hatch="///")

    b3 = ax.bar(x, verify, width, bottom=[w + p for w, p in zip(witness, proof)],
                label="Proof Verification",
                color=[ACCENT_GOLD, ACCENT_GREEN],
                edgecolor="white", linewidth=1, alpha=0.7, zorder=3,
                hatch="...")

    # Total labels on top
    totals = [w + p + v for w, p, v in zip(witness, proof, verify)]
    for i, total in enumerate(totals):
        label = f"{total:.0f} ms" if total < 1000 else f"{total / 1000:.2f} s"
        ax.text(
            x[i], total + max(totals) * 0.02,
            f"Total: {label}",
            ha="center", va="bottom",
            fontsize=10, fontweight="bold", color=TEXT_COLOR,
        )

    # Component labels inside bars
    for i in range(len(labels)):
        # Witness
        if witness[i] > max(totals) * 0.05:
            wlabel = f"{witness[i]:.0f}ms" if witness[i] < 1000 else f"{witness[i] / 1000:.1f}s"
            ax.text(x[i], witness[i] / 2, wlabel,
                    ha="center", va="center", fontsize=8, color="white", fontweight="bold")
        # Proof
        if proof[i] > max(totals) * 0.05:
            plabel = f"{proof[i]:.0f}ms" if proof[i] < 1000 else f"{proof[i] / 1000:.1f}s"
            ax.text(x[i], witness[i] + proof[i] / 2, plabel,
                    ha="center", va="center", fontsize=8, color=TEXT_COLOR, fontweight="bold")

    # Speedup arrow
    speedup = totals[0] / totals[1] if totals[1] > 0 else 0
    mid_y = max(totals) * 0.5
    ax.annotate(
        "", xy=(1, mid_y), xytext=(0, mid_y),
        arrowprops=dict(arrowstyle="-|>", color=ACCENT_GREEN, lw=2.5),
    )
    ax.text(
        0.5, mid_y + max(totals) * 0.05,
        f"{speedup:.1f}× faster",
        ha="center", va="bottom",
        fontsize=12, fontweight="bold", color=ACCENT_GREEN,
    )

    ax.set_ylabel("Time (ms)", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontweight="bold")
    ax.set_ylim(0, max(totals) * 1.20)

    # Custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=FACE_COLOR, alpha=0.9, label="Witness Generation"),
        Patch(facecolor=FACE_COLOR_LIGHT, hatch="///", alpha=0.85, label="Proof Generation"),
        Patch(facecolor=ACCENT_GOLD, hatch="...", alpha=0.7, label="Proof Verification"),
    ]
    ax.legend(handles=legend_elements, loc="upper right", framealpha=0.9)

    ax.set_title(
        "Figure 3: Computational Latency Breakdown",
        fontweight="bold", pad=15,
    )

    plt.tight_layout()
    outpath = os.path.join(output_dir, f"figure3_latency_breakdown.{fmt}")
    fig.savefig(outpath, dpi=300, facecolor="white")
    plt.close(fig)
    print(f"  📊 Saved: {outpath}")


# ============================================================
# Figure 4: On-Chain Gas Breakdown
# ============================================================
def plot_figure4(data, output_dir, fmt):
    """
    Figure 4: Stacked bar of on-chain gas costs
    """
    fig, ax = plt.subplots(figsize=(7, 5))

    labels = ["Face\n(Cosine Similarity)", "Iris\n(Hamming Distance)"]
    x = np.arange(len(labels))
    width = 0.45

    gas = data["figure3_gas"]

    verify = gas["verify_gas"]
    calldata = gas["calldata_gas"]
    nullifier = gas["nullifier_gas"]

    b1 = ax.bar(x, verify, width,
                label="Proof Verification (Pairing + ScalarMul)",
                color=[FACE_COLOR, IRIS_COLOR],
                edgecolor="white", linewidth=1, alpha=0.9, zorder=3)

    b2 = ax.bar(x, calldata, width, bottom=verify,
                label="Calldata (Proof + Public Signals)",
                color=[FACE_COLOR_LIGHT, IRIS_COLOR_LIGHT],
                edgecolor="white", linewidth=1, alpha=0.85, zorder=3, hatch="///")

    b3 = ax.bar(x, nullifier, width,
                bottom=[v + c for v, c in zip(verify, calldata)],
                label="Nullifier Storage (SSTORE)",
                color=[ACCENT_GOLD, ACCENT_GREEN],
                edgecolor="white", linewidth=1, alpha=0.7, zorder=3, hatch="...")

    # Total labels
    totals = [v + c + n for v, c, n in zip(verify, calldata, nullifier)]
    for i, total in enumerate(totals):
        ax.text(
            x[i], total + max(totals) * 0.02,
            f"{total:,} gas",
            ha="center", va="bottom",
            fontsize=10, fontweight="bold", color=TEXT_COLOR,
        )

    # Component labels inside
    for i in range(len(labels)):
        ax.text(x[i], verify[i] / 2, f"{verify[i]:,}",
                ha="center", va="center", fontsize=8, color="white", fontweight="bold")

    # Gas ratio annotation
    ratio = totals[0] / totals[1] if totals[1] > 0 else 1
    ax.text(
        0.5, 0.95,
        f"Gas ratio: {ratio:.2f}× — Groth16 verification is O(1)",
        transform=ax.transAxes,
        ha="center", va="top",
        fontsize=10, fontweight="bold", color="white",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#8E44AD", alpha=0.85, edgecolor="none"),
    )

    ax.set_ylabel("Gas Cost", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontweight="bold")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v / 1000:.0f}K"))
    ax.set_ylim(0, max(totals) * 1.20)

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=FACE_COLOR, alpha=0.9, label="Proof Verification"),
        Patch(facecolor=FACE_COLOR_LIGHT, hatch="///", alpha=0.85, label="Calldata"),
        Patch(facecolor=ACCENT_GOLD, hatch="...", alpha=0.7, label="Nullifier SSTORE"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", framealpha=0.9)

    ax.set_title(
        "Figure 4: On-Chain Gas Cost Breakdown (EIP-1108)",
        fontweight="bold", pad=15,
    )

    plt.tight_layout()
    outpath = os.path.join(output_dir, f"figure4_gas_breakdown.{fmt}")
    fig.savefig(outpath, dpi=300, facecolor="white")
    plt.close(fig)
    print(f"  📊 Saved: {outpath}")


# ============================================================
# Figure 5: Per-Run Scatter (shows consistency)
# ============================================================
def plot_figure5(data, output_dir, fmt):
    """
    Figure 5: Per-run proof generation times (scatter + box)
    Shows consistency and outliers across runs
    """
    raw = data["raw_runs"]
    face_proof = raw["face"]["proof_gen_ms"]
    iris_proof = raw["iris"]["proof_gen_ms"]

    if len(face_proof) < 2 or len(iris_proof) < 2:
        print("  ⚠️  Skipping Figure 5 — need at least 2 runs for scatter plot")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5), sharey=False)

    # Box plots
    bp1 = ax1.boxplot(
        [face_proof, iris_proof],
        labels=["Face", "Iris"],
        patch_artist=True,
        widths=0.5,
        medianprops=dict(color="black", linewidth=2),
        flierprops=dict(marker="o", markersize=6),
    )
    bp1["boxes"][0].set_facecolor(FACE_COLOR)
    bp1["boxes"][0].set_alpha(0.7)
    bp1["boxes"][1].set_facecolor(IRIS_COLOR)
    bp1["boxes"][1].set_alpha(0.7)

    # Scatter overlay
    for i, (vals, color) in enumerate([(face_proof, FACE_COLOR), (iris_proof, IRIS_COLOR)]):
        jitter = np.random.normal(0, 0.04, len(vals))
        ax1.scatter(
            [i + 1 + j for j in jitter], vals,
            color=color, edgecolor="white", s=60, zorder=5, alpha=0.8,
        )

    ax1.set_ylabel("Proof Generation Time (ms)", fontweight="bold")
    ax1.set_title("Proof Generation Distribution", fontweight="bold")

    # Run-by-run line plot
    runs = list(range(1, len(face_proof) + 1))
    ax2.plot(runs, face_proof, "o-", color=FACE_COLOR, label="Face", markersize=8, linewidth=2)
    ax2.plot(runs, iris_proof, "s-", color=IRIS_COLOR, label="Iris", markersize=8, linewidth=2)
    ax2.set_xlabel("Run #", fontweight="bold")
    ax2.set_ylabel("Proof Generation Time (ms)", fontweight="bold")
    ax2.set_title("Per-Run Consistency", fontweight="bold")
    ax2.legend(framealpha=0.9)
    ax2.set_xticks(runs)

    fig.suptitle(
        "Figure 5: Proof Generation Time — Distribution & Consistency",
        fontweight="bold", fontsize=13,
    )

    plt.tight_layout()
    outpath = os.path.join(output_dir, f"figure5_consistency.{fmt}")
    fig.savefig(outpath, dpi=300, facecolor="white")
    plt.close(fig)
    print(f"  📊 Saved: {outpath}")


# ============================================================
# LaTeX Table Output
# ============================================================
def print_latex_tables(data):
    """Print LaTeX-ready table markup for the paper."""
    t1 = data["table1_summary"]
    t2 = data["table2_summary"]

    print("\n" + "=" * 70)
    print("  📝 LaTeX TABLE 1: THE CRYPTOGRAPHIC SHOWDOWN")
    print("=" * 70)
    print(r"""
\begin{table}[htbp]
\centering
\caption{Comparative Analysis of ZK-SNARK Circuit Implementations}
\label{tab:crypto-showdown}
\begin{tabular}{lccc}
\toprule
\textbf{Metric} & \textbf{Face (Cosine)} & \textbf{Iris (Hamming)} & \textbf{Factor} \\
\midrule""")
    print(f"R1CS Constraints & {t1['face_constraints']:,} & {t1['iris_constraints']:,} & {t1['constraint_ratio']:.1f}$\\times$ \\\\")
    print(f"Proving Key Size & {t1['face_zkey_mb']:.2f} MB & {t1['iris_zkey_mb']:.2f} MB & {t1['zkey_ratio']:.1f}$\\times$ \\\\")
    print(f"Witness Gen Time & {t1['face_witness_ms']:.0f} ms & {t1['iris_witness_ms']:.0f} ms & {t1['witness_speedup']:.1f}$\\times$ \\\\")
    print(f"Proof Gen Time & {t1['face_proof_ms']:.0f} ms & {t1['iris_proof_ms']:.0f} ms & {t1['proof_speedup']:.1f}$\\times$ \\\\")
    print(f"Proof Verify Time & {t1['face_verify_ms']:.0f} ms & {t1['iris_verify_ms']:.0f} ms & — \\\\")
    print(f"Proof Payload & {t1['face_proof_bytes']} B & {t1['iris_proof_bytes']} B & $\\approx$1$\\times$ \\\\")
    print(r"""\bottomrule
\end{tabular}
\end{table}""")

    print("\n" + "=" * 70)
    print("  📝 LaTeX TABLE 2: SMART CONTRACT & GAS COSTS")
    print("=" * 70)
    print(r"""
\begin{table}[htbp]
\centering
\caption{On-Chain Verification Cost Comparison (Ethereum, EIP-1108)}
\label{tab:gas-costs}
\begin{tabular}{lccc}
\toprule
\textbf{Metric} & \textbf{Face} & \textbf{Iris} & \textbf{Ratio} \\
\midrule""")
    print(f"Proof Verification Gas & {t2['face_verify_gas']:,} & {t2['iris_verify_gas']:,} & {t2['face_verify_gas'] / t2['iris_verify_gas']:.2f}$\\times$ \\\\")
    print(f"Total Vote TX Gas & {t2['face_total_gas']:,} & {t2['iris_total_gas']:,} & {t2['gas_ratio']:.2f}$\\times$ \\\\")
    face_usd = (t2['face_total_gas'] * 30 * 3000) / 1e18
    iris_usd = (t2['iris_total_gas'] * 30 * 3000) / 1e18
    print(f"Cost @ 30 gwei & \\${face_usd:.4f} & \\${iris_usd:.4f} & — \\\\")
    print(r"""\bottomrule
\end{tabular}
\end{table}""")
    print()


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Generate publication-quality figures from ZKP benchmark results"
    )
    parser.add_argument(
        "--input", "-i",
        default=DEFAULT_INPUT,
        help=f"Path to benchmark_results.json (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--format", "-f",
        default="png",
        choices=["png", "pdf", "svg", "eps"],
        help="Output image format (default: png)",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=300,
        help="Output DPI (default: 300)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for figures (default: same as input)",
    )
    parser.add_argument(
        "--latex",
        action="store_true",
        help="Print LaTeX table markup",
    )
    args = parser.parse_args()

    # Setup
    setup_style()
    plt.rcParams["savefig.dpi"] = args.dpi

    # Load data
    if not os.path.exists(args.input):
        print(f"❌ File not found: {args.input}")
        print(f"   Run the benchmark first: node compareBenchmarks/benchmark_paper.js --runs 5")
        sys.exit(1)

    data = load_data(args.input)

    output_dir = args.output or os.path.dirname(args.input)
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n📁 Output directory: {output_dir}")
    print(f"📐 Format: {args.format.upper()} @ {args.dpi} DPI\n")

    # Generate all figures
    print("Generating figures...\n")
    plot_figure1(data, output_dir, args.format)
    plot_figure2(data, output_dir, args.format)
    plot_figure3(data, output_dir, args.format)
    plot_figure4(data, output_dir, args.format)
    plot_figure5(data, output_dir, args.format)

    # LaTeX tables
    if args.latex:
        print_latex_tables(data)

    print(f"\n✅ All figures saved to: {output_dir}")
    print(f"   Use --latex flag to also print LaTeX table markup")
    print(f"   Use --format pdf for vector graphics (better for papers)")


if __name__ == "__main__":
    main()
