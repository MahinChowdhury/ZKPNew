"""
ZK-SNARK Comprehensive Plot Generator — Figures 1–7
Architecture: Groth16 + Poseidon Merkle Tree + Nullifier
Dual Modality: Face (Cosine Similarity) vs Iris (Hamming Distance)

Reads zksnark_results.json and generates:
  fig1_latency.png       — SNARK Prove & Verify latency (Face vs Iris)
  fig2_complexity.png    — R1CS Constraints & Complexity analysis
  fig3_throughput.png    — Throughput: proofs/sec and ops/sec
  fig4_size_memory.png   — Proof & Key size comparison
  fig5_nullifier.png     — Nullifier double-vote detection accuracy
  fig6_merkle.png        — Merkle Tree scalability vs voter count
  fig7_overview.png      — 6-panel system overview
"""

import json, os, sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import matplotlib.patches as mpatches

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(SCRIPT_DIR, "zksnark_results.json")

with open(INPUT_PATH) as f:
    data = json.load(f)

meta     = data["meta"]
latency  = data["latency"]
thru     = data["throughput"]
arts     = data["artifacts"]
nullif   = data["nullifier"]
merkle   = data["merkle_scalability"]

# ── Global Style ──────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11,
    "axes.labelsize":    10,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
    "savefig.dpi":       300,
    "axes.grid":         True,
    "grid.linestyle":    "--",
    "grid.alpha":        0.35,
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

FACE_COLOR  = "#E74C3C"
IRIS_COLOR  = "#2E86C1"
GREEN       = "#27AE60"
PURPLE      = "#8E44AD"
ORANGE      = "#F39C12"
GRAY        = "#6B7280"
GOLD        = "#F1C40F"
DARK        = "#2C3E50"

ITERS = meta["iterations"]


# ===========================================================================
# FIGURE 1: SNARK Prove & Verify Latency — Face vs Iris
# ===========================================================================
def plot_fig1():
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle(
        f"Figure 1: ZK-SNARK Prove & Verify Latency — Face vs. Iris\n"
        f"(Groth16, {ITERS} iterations, trimmed mean ± σ)",
        fontsize=12, fontweight="bold"
    )

    # Panel (a): Bar chart — Prove & Verify
    ax = axes[0]
    categories = ["Prove", "Verify"]
    face_vals = [latency["face"]["prove"]["trimmedMean"], latency["face"]["verify"]["trimmedMean"]]
    face_sds  = [latency["face"]["prove"]["trimmedSd"],   latency["face"]["verify"]["trimmedSd"]]
    iris_vals = [latency["iris"]["prove"]["trimmedMean"], latency["iris"]["verify"]["trimmedMean"]]
    iris_sds  = [latency["iris"]["prove"]["trimmedSd"],   latency["iris"]["verify"]["trimmedSd"]]

    x = np.arange(len(categories))
    w = 0.35
    b1 = ax.bar(x - w/2, face_vals, w, yerr=face_sds, label="Face (Cosine)", color=FACE_COLOR, alpha=0.85, capsize=5, edgecolor="white")
    b2 = ax.bar(x + w/2, iris_vals, w, yerr=iris_sds, label="Iris (Hamming)", color=IRIS_COLOR, alpha=0.85, capsize=5, edgecolor="white")

    for bar, val in zip(b1, face_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(face_sds)*0.3,
                f"{val:.1f}ms", ha="center", fontsize=8, fontweight="bold", color=FACE_COLOR)
    for bar, val in zip(b2, iris_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(iris_sds)*0.3,
                f"{val:.1f}ms", ha="center", fontsize=8, fontweight="bold", color=IRIS_COLOR)

    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("(a) Prove & Verify latency")
    ax.legend()

    # Panel (b): Full breakdown (Merkle + Nullifier + Prove + Verify)
    ax2 = axes[1]
    phases = ["Merkle\nBuild", "Nullifier\nCompute", "SNARK\nProve", "SNARK\nVerify"]
    face_all = [
        latency["face"]["merkle"]["trimmedMean"],
        latency["face"]["nullifier"]["trimmedMean"],
        latency["face"]["prove"]["trimmedMean"],
        latency["face"]["verify"]["trimmedMean"],
    ]
    iris_all = [
        latency["iris"]["merkle"]["trimmedMean"],
        latency["iris"]["nullifier"]["trimmedMean"],
        latency["iris"]["prove"]["trimmedMean"],
        latency["iris"]["verify"]["trimmedMean"],
    ]

    x2 = np.arange(len(phases))
    ax2.bar(x2 - w/2, face_all, w, color=FACE_COLOR, alpha=0.85, label="Face", edgecolor="white")
    ax2.bar(x2 + w/2, iris_all, w, color=IRIS_COLOR, alpha=0.85, label="Iris", edgecolor="white")

    for i, (fv, iv) in enumerate(zip(face_all, iris_all)):
        if max(fv, iv) > 0:
            ax2.text(i - w/2, fv + 1, f"{fv:.1f}", ha="center", fontsize=7, color=FACE_COLOR)
            ax2.text(i + w/2, iv + 1, f"{iv:.1f}", ha="center", fontsize=7, color=IRIS_COLOR)

    ax2.set_xticks(x2)
    ax2.set_xticklabels(phases)
    ax2.set_ylabel("Latency (ms)")
    ax2.set_title("(b) Full crypto phase breakdown")
    ax2.legend()

    # Panel (c): Distribution (box plot from raw data)
    ax3 = axes[2]
    face_raw = latency["face"]["prove"].get("raw", [])
    iris_raw = latency["iris"]["prove"].get("raw", [])

    if face_raw and iris_raw:
        bp = ax3.boxplot(
            [face_raw, iris_raw],
            labels=["Face Prove", "Iris Prove"],
            patch_artist=True,
            widths=0.5,
            showfliers=True,
            flierprops=dict(marker="o", markersize=3, alpha=0.3),
        )
        bp["boxes"][0].set_facecolor(FACE_COLOR)
        bp["boxes"][0].set_alpha(0.4)
        bp["boxes"][1].set_facecolor(IRIS_COLOR)
        bp["boxes"][1].set_alpha(0.4)
        for median in bp["medians"]:
            median.set_color("black")
            median.set_linewidth(2)

        speedup = latency["face"]["prove"]["trimmedMean"] / latency["iris"]["prove"]["trimmedMean"]
        ax3.text(0.5, 0.92, f"Iris is {speedup:.1f}× faster",
                 transform=ax3.transAxes, ha="center", fontsize=10, fontweight="bold", color=GREEN,
                 bbox=dict(boxstyle="round,pad=0.3", facecolor=GREEN, alpha=0.15))
    else:
        ax3.text(0.5, 0.5, "Raw data not available", transform=ax3.transAxes, ha="center")

    ax3.set_ylabel("Prove Time (ms)")
    ax3.set_title("(c) Proving time distribution")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig1_latency.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 2: R1CS Constraints & Complexity
# ===========================================================================
def plot_fig2():
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(
        "Figure 2: R1CS Constraint Complexity — Face vs. Iris Circuit",
        fontsize=12, fontweight="bold"
    )

    face_c = arts["face"]["constraints"]
    iris_c = arts["iris"]["constraints"]

    # Panel (a): Constraint count bar
    ax = axes[0]
    bars = ax.bar(["Face\n(Cosine Similarity)", "Iris\n(Hamming Distance)"],
                  [face_c, iris_c],
                  color=[FACE_COLOR, IRIS_COLOR], alpha=0.85, width=0.5, edgecolor="white")

    for bar, val in zip(bars, [face_c, iris_c]):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + face_c*0.02,
                f"{val:,}", ha="center", fontsize=10, fontweight="bold")

    reduction = face_c / iris_c if iris_c > 0 else 0
    ax.annotate(
        f"{reduction:.0f}× fewer\nconstraints",
        xy=(1, iris_c), xytext=(0.5, face_c * 0.6),
        fontsize=11, fontweight="bold", color=GREEN,
        arrowprops=dict(arrowstyle="->", color=GREEN, lw=2),
        ha="center",
    )

    ax.set_ylabel("R1CS Constraints")
    ax.set_title("(a) Circuit constraint count")

    # Panel (b): Constraints vs Prove Time scatter
    ax2 = axes[1]
    face_prove_ms = latency["face"]["prove"]["trimmedMean"]
    iris_prove_ms = latency["iris"]["prove"]["trimmedMean"]

    ax2.scatter([face_c], [face_prove_ms], s=200, c=FACE_COLOR, marker="o",
                zorder=5, label=f"Face ({face_c:,} constraints)")
    ax2.scatter([iris_c], [iris_prove_ms], s=200, c=IRIS_COLOR, marker="s",
                zorder=5, label=f"Iris ({iris_c:,} constraints)")

    # Connect with arrow
    ax2.annotate("", xy=(iris_c, iris_prove_ms), xytext=(face_c, face_prove_ms),
                 arrowprops=dict(arrowstyle="->", color=GRAY, lw=1.5, linestyle="--"))

    ax2.text((face_c + iris_c)/2, (face_prove_ms + iris_prove_ms)/2 + face_prove_ms*0.05,
             f"{reduction:.0f}× fewer constraints\n→ {face_prove_ms/iris_prove_ms:.0f}× faster proving",
             ha="center", fontsize=9, fontweight="bold", color=DARK,
             bbox=dict(boxstyle="round,pad=0.3", facecolor="#ECF0F1", alpha=0.9))

    ax2.set_xlabel("R1CS Constraints")
    ax2.set_ylabel("Proving Time (ms)")
    ax2.set_title("(b) Constraints vs. proving time")
    ax2.legend()

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig2_complexity.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 3: Throughput — Proofs per Second
# ===========================================================================
def plot_fig3():
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(
        "Figure 3: ZK-SNARK Throughput — Face vs. Iris",
        fontsize=12, fontweight="bold"
    )

    # Panel (a): Proofs per second & verifications per second
    ax = axes[0]
    categories = ["Prove\n(proofs/sec)", "Verify\n(verif/sec)"]
    face_th = [thru["face"]["prove_per_sec"], thru["face"]["verify_per_sec"]]
    iris_th = [thru["iris"]["prove_per_sec"], thru["iris"]["verify_per_sec"]]

    x = np.arange(len(categories))
    w = 0.35
    b1 = ax.bar(x - w/2, face_th, w, color=FACE_COLOR, alpha=0.85, label="Face", edgecolor="white")
    b2 = ax.bar(x + w/2, iris_th, w, color=IRIS_COLOR, alpha=0.85, label="Iris", edgecolor="white")

    for bar, val in zip(b1, face_th):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(face_th)*0.02,
                f"{val:.1f}", ha="center", fontsize=9, fontweight="bold", color=FACE_COLOR)
    for bar, val in zip(b2, iris_th):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(iris_th)*0.02,
                f"{val:.1f}", ha="center", fontsize=9, fontweight="bold", color=IRIS_COLOR)

    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylabel("Operations per second")
    ax.set_title("(a) Throughput comparison")
    ax.legend()

    # Panel (b): Time per operation (log scale)
    ax2 = axes[1]
    ops = ["Merkle\nBuild", "Nullifier", "Prove", "Verify"]
    face_times = [
        latency["face"]["merkle"]["trimmedMean"],
        latency["face"]["nullifier"]["trimmedMean"],
        latency["face"]["prove"]["trimmedMean"],
        latency["face"]["verify"]["trimmedMean"],
    ]
    iris_times = [
        latency["iris"]["merkle"]["trimmedMean"],
        latency["iris"]["nullifier"]["trimmedMean"],
        latency["iris"]["prove"]["trimmedMean"],
        latency["iris"]["verify"]["trimmedMean"],
    ]

    x2 = np.arange(len(ops))
    ax2.bar(x2 - w/2, face_times, w, color=FACE_COLOR, alpha=0.85, label="Face", edgecolor="white")
    ax2.bar(x2 + w/2, iris_times, w, color=IRIS_COLOR, alpha=0.85, label="Iris", edgecolor="white")
    ax2.set_yscale("log")
    ax2.set_xticks(x2)
    ax2.set_xticklabels(ops)
    ax2.set_ylabel("Time per operation (ms) [log]")
    ax2.set_title("(b) Per-operation time (log scale)")
    ax2.legend()

    # 1-second threshold line
    ax2.axhline(y=1000, color=ORANGE, linestyle=":", linewidth=1.2, alpha=0.7)
    ax2.text(len(ops)-0.5, 1050, "1 second threshold", fontsize=8, color=ORANGE, style="italic")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig3_throughput.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 4: Proof & Key Size Comparison
# ===========================================================================
def plot_fig4():
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle(
        "Figure 4: ZK-SNARK Artifact Size Comparison — Face vs. Iris",
        fontsize=12, fontweight="bold"
    )

    # Panel (a): Proving key (zkey) size
    ax = axes[0]
    face_zkey = arts["face"]["zkey_mb"]
    iris_zkey = arts["iris"]["zkey_mb"]

    bars = ax.bar(["Face", "Iris"], [face_zkey, iris_zkey],
                  color=[FACE_COLOR, IRIS_COLOR], alpha=0.85, width=0.5, edgecolor="white")
    for bar, val in zip(bars, [face_zkey, iris_zkey]):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + face_zkey*0.02,
                f"{val:.2f} MB", ha="center", fontsize=9, fontweight="bold")

    reduction = face_zkey / iris_zkey if iris_zkey > 0 else 0
    ax.annotate(f"{reduction:.0f}× smaller", xy=(1, iris_zkey),
                xytext=(0.5, face_zkey * 0.5),
                fontsize=10, fontweight="bold", color=GREEN,
                arrowprops=dict(arrowstyle="->", color=GREEN, lw=1.5), ha="center")

    ax.set_ylabel("Size (MB)")
    ax.set_title("(a) Proving key (zkey) size")

    # Panel (b): WASM circuit size
    ax2 = axes[1]
    face_wasm = arts["face"]["wasm_kb"]
    iris_wasm = arts["iris"]["wasm_kb"]

    bars2 = ax2.bar(["Face", "Iris"], [face_wasm, iris_wasm],
                    color=[FACE_COLOR, IRIS_COLOR], alpha=0.85, width=0.5, edgecolor="white")
    for bar, val in zip(bars2, [face_wasm, iris_wasm]):
        label = f"{val:.0f} KB" if val < 1024 else f"{val/1024:.2f} MB"
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + face_wasm*0.02,
                 label, ha="center", fontsize=9, fontweight="bold")

    ax2.set_ylabel("Size (KB)")
    ax2.set_title("(b) WASM circuit size")

    # Panel (c): Proof & public signals (on-chain)
    ax3 = axes[2]
    labels = ["Proof\n(JSON)", "Public\nSignals"]
    face_onchain = [arts["face"]["proof_bytes"], arts["face"]["public_signals_bytes"]]
    iris_onchain = [arts["iris"]["proof_bytes"], arts["iris"]["public_signals_bytes"]]

    x3 = np.arange(len(labels))
    w = 0.35
    b1 = ax3.bar(x3 - w/2, face_onchain, w, color=FACE_COLOR, alpha=0.85, label="Face", edgecolor="white")
    b2 = ax3.bar(x3 + w/2, iris_onchain, w, color=IRIS_COLOR, alpha=0.85, label="Iris", edgecolor="white")

    for bar, val in zip(b1, face_onchain):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                 f"{val}B", ha="center", fontsize=8, color=FACE_COLOR)
    for bar, val in zip(b2, iris_onchain):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                 f"{val}B", ha="center", fontsize=8, color=IRIS_COLOR)

    ax3.set_xticks(x3)
    ax3.set_xticklabels(labels)
    ax3.set_ylabel("Size (bytes)")
    ax3.set_title("(c) On-chain proof data size")
    ax3.legend()

    # Note: Groth16 proof size is constant (3 group elements)
    ax3.text(0.5, 0.02, "Note: Groth16 proofs are constant-size (3 curve points ≈ 192 bytes)",
             transform=ax3.transAxes, ha="center", fontsize=7, style="italic", color=GRAY)

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig4_size_memory.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 5: Nullifier Double-Vote Detection
# ===========================================================================
def plot_fig5():
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle(
        f"Figure 5: Nullifier-Based Double-Vote Detection ({nullif['trials']} trials per test)",
        fontsize=12, fontweight="bold"
    )

    # Panel (a): Detection accuracy
    ax = axes[0]
    categories = ["True Positives\n(same voter detected)", "True Negatives\n(diff voter cleared)"]
    values = [nullif["true_positives"], nullif["true_negatives"]]
    colors_bar = [GREEN, IRIS_COLOR]
    total = nullif["trials"]

    bars = ax.bar(categories, values, color=colors_bar, alpha=0.85, width=0.5, edgecolor="white")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + total*0.01,
                f"{val}/{total}", ha="center", fontsize=11, fontweight="bold")

    ax.axhline(y=total, color=GRAY, linestyle="--", linewidth=1, alpha=0.5, label=f"Total = {total}")
    ax.set_ylabel(f"Count (out of {total} trials)")
    ax.set_title("(a) Detection accuracy: 100%")
    ax.legend()

    # Panel (b): Cross-election isolation
    ax2 = axes[1]
    cross_vals = [nullif["cross_election_true_negatives"]]
    bars2 = ax2.bar(["Cross-Election\nIsolation"], cross_vals, color=[PURPLE], alpha=0.85, width=0.4, edgecolor="white")
    ax2.text(bars2[0].get_x() + bars2[0].get_width()/2, bars2[0].get_height() + total*0.01,
             f"{cross_vals[0]}/{total}", ha="center", fontsize=11, fontweight="bold")
    ax2.axhline(y=total, color=GRAY, linestyle="--", linewidth=1, alpha=0.5)
    ax2.set_ylabel(f"Count (out of {total})")
    ax2.set_title("(b) Cross-election nullifier isolation")

    ax2.text(0.5, 0.15,
             "Same voter, different election → different nullifier\n"
             "Prevents tracking across elections",
             transform=ax2.transAxes, ha="center", fontsize=8, style="italic",
             bbox=dict(boxstyle="round,pad=0.3", facecolor=PURPLE, alpha=0.1))

    # Panel (c): Nullifier compute time
    ax3 = axes[2]
    compute_ms = nullif["compute_time"]["trimmedMean"]
    compute_sd = nullif["compute_time"]["trimmedSd"]

    bars3 = ax3.bar(["Nullifier\nCompute"], [compute_ms], yerr=[compute_sd],
                    color=[ORANGE], alpha=0.85, width=0.4, capsize=5, edgecolor="white")
    ax3.text(bars3[0].get_x() + bars3[0].get_width()/2, bars3[0].get_height() + compute_sd + 0.01,
             f"{compute_ms:.2f} ms", ha="center", fontsize=11, fontweight="bold")

    ax3.set_ylabel("Latency (ms)")
    ax3.set_title("(c) Poseidon nullifier computation time")

    ax3.text(0.5, 0.85,
             f"Nullifier = Poseidon(secretKey, electionId)\nO(1) check via on-chain registry",
             transform=ax3.transAxes, ha="center", fontsize=8,
             bbox=dict(boxstyle="round,pad=0.3", facecolor=ORANGE, alpha=0.15))

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig5_nullifier.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 6: Merkle Tree Scalability
# ===========================================================================
def plot_fig6():
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle(
        "Figure 6: Poseidon Merkle Tree Scalability vs. Voter Count",
        fontsize=12, fontweight="bold"
    )

    ns = [m["voters"] for m in merkle]
    build_means = [m["build"]["trimmedMean"] for m in merkle]
    build_sds   = [m["build"]["trimmedSd"]   for m in merkle]
    proof_means = [m["proof_gen"]["trimmedMean"] for m in merkle]
    proof_sds   = [m["proof_gen"]["trimmedSd"]   for m in merkle]

    # Panel (a): Build time vs N
    ax = axes[0]
    ax.errorbar(ns, build_means, yerr=build_sds, fmt="o-", color=IRIS_COLOR, lw=2, capsize=3, ms=6,
                label="Merkle Tree Build")
    ax.errorbar(ns, proof_means, yerr=proof_sds, fmt="s--", color=GREEN, lw=2, capsize=3, ms=5,
                label="Single Proof Gen", alpha=0.7)

    # O(n) fit for build
    coeff = np.polyfit(ns, build_means, 1)
    fit_x = np.linspace(ns[0], ns[-1], 100)
    ax.plot(fit_x, np.polyval(coeff, fit_x), ":", color=GRAY, lw=1.2,
            label=f"Linear fit: {coeff[0]:.3f}n + {coeff[1]:.2f}")

    ax.set_xlabel("Number of registered voters")
    ax.set_ylabel("Latency (ms)")
    ax.set_title("(a) Build & proof generation time")
    ax.legend(fontsize=8)

    # Annotate O(n·log n) for build
    ax.text(0.55, 0.85, "Build: O(n) Poseidon hashes\nProof: O(log n) path extraction",
            transform=ax.transAxes, fontsize=8, color=DARK,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#EBF5FB", alpha=0.9))

    # Panel (b): Log-log to confirm O(n) scaling
    ax2 = axes[1]
    ax2.loglog(ns, build_means, "o-", color=IRIS_COLOR, lw=2, ms=6, label="Measured build time")

    # O(n) reference line
    ref_ns = np.array(ns)
    ref_y = build_means[0] * (ref_ns / ref_ns[0])
    ax2.loglog(ns, ref_y, ":", color=GRAY, lw=1.5, alpha=0.6, label="O(n) reference")

    ax2.set_xlabel("Number of voters [log]")
    ax2.set_ylabel("Build time (ms) [log]")
    ax2.set_title("(b) Log-log scaling confirmation")
    ax2.legend(fontsize=8)

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    path_out = os.path.join(SCRIPT_DIR, "fig6_merkle.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# FIGURE 7: System 6-Panel Overview
# ===========================================================================
def plot_fig7():
    fig = plt.figure(figsize=(18, 11))
    gs = GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)
    fig.suptitle(
        f"ZK-SNARK Biometric Voting System — Performance Overview\n"
        f"Groth16 + Poseidon Merkle Tree + Nullifier | {ITERS} iterations | {meta['date'][:10]}",
        fontsize=13, fontweight="bold"
    )

    # (a) Prove & Verify latency
    ax1 = fig.add_subplot(gs[0, 0])
    cats = ["Prove", "Verify"]
    face_v = [latency["face"]["prove"]["trimmedMean"], latency["face"]["verify"]["trimmedMean"]]
    iris_v = [latency["iris"]["prove"]["trimmedMean"], latency["iris"]["verify"]["trimmedMean"]]
    x = np.arange(len(cats)); w = 0.35
    ax1.bar(x - w/2, face_v, w, color=FACE_COLOR, alpha=0.85, label="Face")
    ax1.bar(x + w/2, iris_v, w, color=IRIS_COLOR, alpha=0.85, label="Iris")
    ax1.set_xticks(x); ax1.set_xticklabels(cats)
    ax1.set_ylabel("Latency (ms)")
    ax1.set_title("(a) Latency (mean ± σ)")
    ax1.legend(fontsize=8)

    # (b) Throughput
    ax2 = fig.add_subplot(gs[0, 1])
    cats2 = ["Prove", "Verify"]
    face_th = [thru["face"]["prove_per_sec"], thru["face"]["verify_per_sec"]]
    iris_th = [thru["iris"]["prove_per_sec"], thru["iris"]["verify_per_sec"]]
    x2 = np.arange(len(cats2))
    ax2.bar(x2 - w/2, face_th, w, color=FACE_COLOR, alpha=0.85, label="Face")
    ax2.bar(x2 + w/2, iris_th, w, color=IRIS_COLOR, alpha=0.85, label="Iris")
    ax2.set_xticks(x2); ax2.set_xticklabels(cats2)
    ax2.set_ylabel("ops/sec")
    ax2.set_title("(b) Throughput")
    ax2.legend(fontsize=8)

    # (c) Artifact sizes
    ax3 = fig.add_subplot(gs[0, 2])
    size_cats = ["zkey\n(MB)", "WASM\n(KB)", "Proof\n(B)"]
    face_sz = [arts["face"]["zkey_mb"], arts["face"]["wasm_kb"]/1024, arts["face"]["proof_bytes"]/1024]
    iris_sz = [arts["iris"]["zkey_mb"], arts["iris"]["wasm_kb"]/1024, arts["iris"]["proof_bytes"]/1024]
    x3 = np.arange(len(size_cats))
    ax3.bar(x3 - w/2, face_sz, w, color=FACE_COLOR, alpha=0.85, label="Face")
    ax3.bar(x3 + w/2, iris_sz, w, color=IRIS_COLOR, alpha=0.85, label="Iris")
    ax3.set_xticks(x3); ax3.set_xticklabels(size_cats)
    ax3.set_ylabel("Size (MB / normalized)")
    ax3.set_title("(c) Artifact sizes")
    ax3.legend(fontsize=8)

    # (d) Constraint comparison
    ax4 = fig.add_subplot(gs[1, 0])
    face_c = arts["face"]["constraints"]
    iris_c = arts["iris"]["constraints"]
    bars4 = ax4.bar(["Face", "Iris"], [face_c, iris_c], color=[FACE_COLOR, IRIS_COLOR], alpha=0.85, width=0.5)
    for bar, val in zip(bars4, [face_c, iris_c]):
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + face_c*0.02,
                 f"{val:,}", ha="center", fontsize=9, fontweight="bold")
    ax4.set_ylabel("R1CS Constraints")
    ax4.set_title("(d) Circuit complexity")

    # (e) Double-vote detection
    ax5 = fig.add_subplot(gs[1, 1])
    det_cats = ["TP", "TN", "Cross-Election"]
    det_vals = [nullif["true_positives"], nullif["true_negatives"], nullif["cross_election_true_negatives"]]
    det_colors = [GREEN, IRIS_COLOR, PURPLE]
    bars5 = ax5.bar(det_cats, det_vals, color=det_colors, alpha=0.85, width=0.5)
    ax5.axhline(y=nullif["trials"], color=GRAY, linestyle="--", linewidth=1, alpha=0.5)
    for bar, val in zip(bars5, det_vals):
        ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + nullif["trials"]*0.01,
                 f"{val}/{nullif['trials']}", ha="center", fontsize=8, fontweight="bold")
    ax5.set_ylabel("Count")
    ax5.set_title("(e) Nullifier detection (100%)")

    # (f) Merkle scalability
    ax6 = fig.add_subplot(gs[1, 2])
    ns = [m["voters"] for m in merkle]
    build_ms = [m["build"]["trimmedMean"] for m in merkle]
    ax6.plot(ns, build_ms, "o-", color=IRIS_COLOR, lw=2, ms=5, label="Merkle build")
    ax6.set_xlabel("Voters")
    ax6.set_ylabel("Build time (ms)")
    ax6.set_title("(f) Merkle tree scalability")
    ax6.legend(fontsize=8)

    path_out = os.path.join(SCRIPT_DIR, "fig7_overview.png")
    fig.savefig(path_out, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  📊 Saved {path_out}")


# ===========================================================================
# MAIN
# ===========================================================================
if __name__ == "__main__":
    print(f"\nGenerating figures from zksnark_results.json ({ITERS} iterations)...\n")

    plot_fig1()
    plot_fig2()
    plot_fig3()
    plot_fig4()
    plot_fig5()
    plot_fig6()
    plot_fig7()

    print(f"\n✅ All 7 figures generated in {SCRIPT_DIR}/")
    print(f"   fig8_homomorphic.png is generated separately by homomorphic_plot.py\n")
