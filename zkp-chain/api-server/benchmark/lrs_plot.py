"""
LRS Plot Generator  —  reads lrs_results.json produced by lrs_benchmark.js
Outputs 7 publication-quality PNG figures (300 DPI, Times New Roman)

Supports extended ring sizes: [2, 4, 8, 16, 32, 64, 128, 256, 512, 1000]

Run:  python lrs_plot.py
Requires:  pip install matplotlib numpy
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.gridspec import GridSpec

# ── load results ──────────────────────────────────────────────────────────────

with open("lrs_results.json") as f:
    data = json.load(f)

meta       = data["meta"]
latency    = data["latency"]
sig_size   = data["sig_size"]
throughput = data["throughput"]
memory     = data["memory"]
link       = data["linkability"]
sim        = data["simulation"]

# unpack into arrays
ns           = np.array([d["n"]                  for d in latency])
sign_mean    = np.array([d["sign"]["mean"]        for d in latency])
sign_sd      = np.array([d["sign"]["sd"]          for d in latency])
sign_p95     = np.array([d["sign"]["p95"]         for d in latency])
sign_p99     = np.array([d["sign"]["p99"]         for d in latency])
verify_mean  = np.array([d["verify"]["mean"]      for d in latency])
verify_sd    = np.array([d["verify"]["sd"]        for d in latency])
verify_p95   = np.array([d["verify"]["p95"]       for d in latency])
verify_p99   = np.array([d["verify"]["p99"]       for d in latency])

tp_ns        = np.array([d["n"]                  for d in throughput])
sign_ops     = np.array([d["sign_ops"]            for d in throughput])
verify_ops   = np.array([d["verify_ops"]          for d in throughput])

json_bytes   = np.array([d["json_bytes"]          for d in sig_size])
compact_bytes= np.array([d["compact_bytes"]       for d in sig_size])

mem_ns       = np.array([d["n"]                  for d in memory])
mem_delta    = np.array([d["delta_mb"]            for d in memory])

sim_voters   = np.array([d["voters"]              for d in sim])
sim_ring     = np.array([d["ring_size"]           for d in sim])
sim_total_s  = np.array([d["total_ms"]            for d in sim]) / 1000
sim_vps      = np.array([d["votes_per_sec"]       for d in sim])
sim_sign_ms  = np.array([d["avg_sign_ms"]         for d in sim])
sim_verify_ms= np.array([d["avg_verify_ms"]       for d in sim])

# ── global style ──────────────────────────────────────────────────────────────

plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11,
    "axes.labelsize":    10,
    "xtick.labelsize":   8,
    "ytick.labelsize":   9,
    "legend.fontsize":   8,
    "figure.dpi":        150,
    "savefig.dpi":       300,
    "axes.grid":         True,
    "grid.linestyle":    "--",
    "grid.alpha":        0.4,
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

BLUE   = "#2563EB"
RED    = "#DC2626"
GREEN  = "#16A34A"
AMBER  = "#D97706"
PURPLE = "#7C3AED"
GRAY   = "#6B7280"

def save(fig, name):
    fig.tight_layout()
    fig.savefig(name, bbox_inches="tight", dpi=300)
    plt.close(fig)
    print(f"  Saved {name}")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 1 — Latency (mean ± σ) with scalability threshold markers
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Figure 1: Sign & Verify Latency vs. Ring Size", fontsize=11, fontweight="bold")

ax = axes[0]
ax.errorbar(ns, sign_mean,   yerr=sign_sd,   fmt="-o", color=BLUE, capsize=4, linewidth=1.8, markersize=4, label="Sign (mean ± σ)")
ax.errorbar(ns, verify_mean, yerr=verify_sd, fmt="-s", color=RED,  capsize=4, linewidth=1.8, markersize=4, label="Verify (mean ± σ)")

# Scalability threshold lines
ax.axhline(1000, color=GRAY, linestyle=":", linewidth=1.5, alpha=0.7)
ax.text(ns[0] + 1, 1050, "1 second threshold", fontsize=7, color=GRAY, style="italic")
ax.axhline(500, color=AMBER, linestyle=":", linewidth=1.2, alpha=0.5)
ax.text(ns[0] + 1, 530, "acceptable UX (500ms)", fontsize=7, color=AMBER, style="italic")

ax.set_xlabel("Ring size (n)")
ax.set_ylabel("Latency (ms)")
ax.set_title("(a) Mean latency with std deviation")
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns)
ax.legend(loc="upper left")

ax = axes[1]
ax.plot(ns, sign_p95,    "--^", color=BLUE, linewidth=1.8, markersize=4, label="Sign P95")
ax.plot(ns, sign_p99,    ":^",  color=BLUE, linewidth=1.4, markersize=3, label="Sign P99", alpha=0.7)
ax.plot(ns, verify_p95,  "--v", color=RED,  linewidth=1.8, markersize=4, label="Verify P95")
ax.plot(ns, verify_p99,  ":v",  color=RED,  linewidth=1.4, markersize=3, label="Verify P99", alpha=0.7)
ax.axhline(1000, color=GRAY, linestyle=":", linewidth=1.5, alpha=0.7)
ax.text(ns[0] + 1, 1050, "1 second threshold", fontsize=7, color=GRAY, style="italic")
ax.set_xlabel("Ring size (n)")
ax.set_ylabel("Latency (ms)")
ax.set_title("(b) P95 / P99 tail latency")
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns)
ax.legend(ncol=2, fontsize=7, loc="upper left")

save(fig, "fig1_latency.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 2 — O(n) Complexity Confirmation
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Figure 2: O(n) Linear Complexity Confirmation", fontsize=11, fontweight="bold")

c_sign   = np.polyfit(ns, sign_mean,   1)
c_verify = np.polyfit(ns, verify_mean, 1)
fit_x    = np.linspace(ns[0] - 1, ns[-1] + 50, 300)
r2_sign   = 1 - np.sum((sign_mean   - np.polyval(c_sign,   ns))**2) / np.sum((sign_mean   - sign_mean.mean())**2)
r2_verify = 1 - np.sum((verify_mean - np.polyval(c_verify, ns))**2) / np.sum((verify_mean - verify_mean.mean())**2)

ax = axes[0]
ax.scatter(ns, sign_mean,   color=BLUE, zorder=5, s=30, label="Sign (measured)")
ax.scatter(ns, verify_mean, color=RED,  zorder=5, s=30, label="Verify (measured)")
ax.plot(fit_x, np.polyval(c_sign,   fit_x), "--", color=BLUE, linewidth=1.4,
        label=f"Sign fit: {c_sign[0]:.3f}n+{c_sign[1]:.1f}  R²={r2_sign:.4f}")
ax.plot(fit_x, np.polyval(c_verify, fit_x), "--", color=RED,  linewidth=1.4,
        label=f"Verify fit: {c_verify[0]:.3f}n+{c_verify[1]:.1f}  R²={r2_verify:.4f}")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Latency (ms)")
ax.set_title("(a) Linear regression on measured data")
ax.legend(fontsize=7)

ax = axes[1]
ax.loglog(ns, sign_mean,   "-o", color=BLUE, linewidth=1.8, markersize=4, label="Sign")
ax.loglog(ns, verify_mean, "-s", color=RED,  linewidth=1.8, markersize=4, label="Verify")
ref = ns * (sign_mean[0] / ns[0])
ax.loglog(ns, ref, ":", color=GRAY, linewidth=1.2, label="O(n) reference")
ax.set_xlabel("Ring size (n)  [log]"); ax.set_ylabel("Latency (ms)  [log]")
ax.set_title("(b) Log–log plot (slope ≈ 1 → O(n))")
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns); ax.legend()

save(fig, "fig2_complexity.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 3 — Throughput
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Figure 3: Throughput vs. Ring Size", fontsize=11, fontweight="bold")

x = np.arange(len(tp_ns)); w = 0.35
ax = axes[0]
bars1 = ax.bar(x - w/2, sign_ops,   width=w, color=BLUE, alpha=0.85, label="Sign")
bars2 = ax.bar(x + w/2, verify_ops, width=w, color=RED,  alpha=0.85, label="Verify")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Operations per second")
ax.set_title("(a) Throughput (ops/sec)")
ax.set_xticks(x); ax.set_xticklabels(tp_ns, fontsize=7); ax.legend()
for bar in bars1:
    if bar.get_height() > 0:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{bar.get_height():.1f}", ha="center", fontsize=6)
for bar in bars2:
    if bar.get_height() > 0:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{bar.get_height():.1f}", ha="center", fontsize=6)

ax = axes[1]
# Avoid division by zero for any near-zero throughput
safe_sign = np.where(sign_ops > 0, 1000 / sign_ops, 0)
safe_verify = np.where(verify_ops > 0, 1000 / verify_ops, 0)
ax.semilogy(tp_ns, safe_sign,   "-o", color=BLUE, linewidth=1.8, markersize=4, label="Sign")
ax.semilogy(tp_ns, safe_verify, "-s", color=RED,  linewidth=1.8, markersize=4, label="Verify")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Time per op (ms)  [log]")
ax.set_title("(b) Time per operation (log scale)")
ax.set_xticks(tp_ns); ax.xaxis.set_major_formatter(ticker.ScalarFormatter()); ax.legend()

save(fig, "fig3_throughput.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 4 — Signature Size & Memory
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Figure 4: Signature Size & Memory Usage vs. Ring Size", fontsize=11, fontweight="bold")

ax = axes[0]
ax.plot(ns, json_bytes / 1024,    "-o", color=BLUE,  linewidth=1.8, markersize=4, label="JSON (transmitted)")
ax.plot(ns, compact_bytes / 1024, "--s", color=GREEN, linewidth=1.8, markersize=4, label="Compact: 32+32n+64 B")
ax.fill_between(ns, compact_bytes / 1024, json_bytes / 1024, alpha=0.1, color=BLUE, label="Encoding overhead")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Signature size (KB)")
ax.set_title("(a) Signature size (linear growth)")
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns); ax.legend(fontsize=7)
# Annotate key sizes
for n, j in zip(ns, json_bytes):
    if n in [2, 64, 256, 1000]:
        ax.annotate(f"{j/1024:.1f}KB", (n, j/1024), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=6, color=BLUE)

ax = axes[1]
ax.plot(mem_ns, mem_delta, "-o", color=PURPLE, linewidth=1.8, markersize=4, label="Heap delta (sign)")
ax.axhline(0, color=GRAY, linestyle="-", linewidth=0.5, alpha=0.5)
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Heap usage delta (MB)")
ax.set_title("(b) Memory usage per sign operation")
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(mem_ns); ax.legend()

save(fig, "fig4_size_memory.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 5 — Linkability / Double-Vote Detection
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
fig.suptitle("Figure 5: Linkability — Double-Vote Detection", fontsize=11, fontweight="bold")

acc = link["accuracy_pct"]
tp  = link["true_positives"]
tn  = link["true_negatives"]
iters = link["iterations"]

ax = axes[0]
categories = ["True Positives\n(same voter detected)", "True Negatives\n(diff voter cleared)"]
values = [tp, tn]
colors = [GREEN, BLUE]
bars = ax.bar(categories, values, color=colors, alpha=0.85, width=0.4)
ax.set_ylim(0, iters * 1.15)
ax.set_ylabel("Count (out of {} trials)".format(iters))
ax.set_title(f"(a) Detection accuracy: {acc}%")
for bar, v in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
            f"{v}/{iters}", ha="center", fontsize=10, fontweight="bold")
ax.axhline(iters, color=GRAY, linestyle="--", linewidth=1, alpha=0.5, label=f"Total = {iters}")
ax.legend()

ax = axes[1]
check_mean_us = link["check_time"]["mean"] * 1000
check_sd_us   = link["check_time"]["sd"]   * 1000
ax.bar(["Link tag\ncomparison"], [check_mean_us], yerr=[check_sd_us],
       color=PURPLE, alpha=0.85, width=0.3, capsize=8)
ax.set_ylabel("Check time (μs)")
ax.set_title("(b) O(1) link tag check time")
ax.text(0, check_mean_us + check_sd_us + 0.0002,
        f"{check_mean_us:.4f} μs", ha="center", fontsize=10)
ax.set_ylim(0, check_mean_us * 3)

save(fig, "fig5_linkability.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 6 — End-to-End Voting Simulation (ring_size = voters)
# ═══════════════════════════════════════════════════════════════════════════════

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Figure 6: End-to-End Voting Simulation (ring size = voters)", fontsize=11, fontweight="bold")

ax = axes[0]
ax.plot(sim_voters, sim_total_s, "-o", color=BLUE, linewidth=1.8, markersize=5, label="Total wall time")
ax.set_xlabel("Number of voters (= ring size)")
ax.set_ylabel("Total wall time (s)")
ax.set_title("(a) Total time (scales quadratically: n voters × O(n) per vote)")
ax.legend()

# Add quadratic fit since total = n * O(n) = O(n²)
if len(sim_voters) > 2:
    c_quad = np.polyfit(sim_voters, sim_total_s, 2)
    fit_x = np.linspace(sim_voters[0], sim_voters[-1], 200)
    ax.plot(fit_x, np.polyval(c_quad, fit_x), "--", color=GRAY, linewidth=1.2,
            label=f"Quadratic fit: {c_quad[0]:.6f}n²")
    ax.legend(fontsize=7)

ax = axes[1]
ax.plot(sim_voters, sim_sign_ms, "-o", color=BLUE, linewidth=1.8, markersize=5, label="Avg sign (ms)")
ax.plot(sim_voters, sim_verify_ms, "-s", color=RED, linewidth=1.8, markersize=5, label="Avg verify (ms)")
ax.set_xlabel("Number of voters (= ring size)")
ax.set_ylabel("Average latency per vote (ms)")
ax.set_title("(b) Per-vote latency grows with ring size")
ax.legend()

save(fig, "fig6_simulation.png")


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 7 — Combined Overview (use in paper abstract / overview section)
# ═══════════════════════════════════════════════════════════════════════════════

fig = plt.figure(figsize=(16, 10))
gs  = GridSpec(2, 3, figure=fig, hspace=0.48, wspace=0.38)
fig.suptitle(
    f"LRS Performance Overview — ZKP Blockchain Voting System\n"
    f"Liu–Wei–Wong on secp256k1  |  {meta['iterations']} iterations  |  {meta['date'][:10]}",
    fontsize=12, fontweight="bold"
)

# (a) Latency
ax = fig.add_subplot(gs[0, 0])
ax.errorbar(ns, sign_mean,   yerr=sign_sd,   fmt="-o", color=BLUE, capsize=3, linewidth=1.5, markersize=3, label="Sign")
ax.errorbar(ns, verify_mean, yerr=verify_sd, fmt="-s", color=RED,  capsize=3, linewidth=1.5, markersize=3, label="Verify")
ax.axhline(1000, color=GRAY, linestyle=":", linewidth=1, alpha=0.6)
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Latency (ms)")
ax.set_title("(a) Latency (mean ± σ)"); ax.legend(fontsize=7)
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns)

# (b) Throughput
ax = fig.add_subplot(gs[0, 1])
ax.plot(tp_ns, sign_ops,   "-o", color=BLUE, linewidth=1.5, markersize=3, label="Sign")
ax.plot(tp_ns, verify_ops, "-s", color=RED,  linewidth=1.5, markersize=3, label="Verify")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("ops/sec")
ax.set_title("(b) Throughput"); ax.legend(fontsize=7)
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(tp_ns)

# (c) Signature size
ax = fig.add_subplot(gs[0, 2])
ax.plot(ns, json_bytes / 1024,    "-o",  color=BLUE,  linewidth=1.5, markersize=3, label="JSON")
ax.plot(ns, compact_bytes / 1024, "--s", color=GREEN, linewidth=1.5, markersize=3, label="Compact")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Size (KB)")
ax.set_title("(c) Signature size"); ax.legend(fontsize=7)
ax.set_xscale("log", base=2)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns)

# (d) Linear complexity confirmation (log-log)
ax = fig.add_subplot(gs[1, 0])
ax.loglog(ns, sign_mean,   "-o", color=BLUE, linewidth=1.5, markersize=3, label="Sign")
ax.loglog(ns, verify_mean, "-s", color=RED,  linewidth=1.5, markersize=3, label="Verify")
ref = ns * (sign_mean[0] / ns[0])
ax.loglog(ns, ref, ":", color=GRAY, linewidth=1, label="O(n) reference")
ax.set_xlabel("Ring size (n)"); ax.set_ylabel("Latency (ms)")
ax.set_title("(d) O(n) complexity (log-log)"); ax.legend(fontsize=7)
ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.set_xticks(ns)

# (e) Linkability
ax = fig.add_subplot(gs[1, 1])
ax.bar(["TP", "TN"], [link["true_positives"], link["true_negatives"]],
       color=[GREEN, BLUE], alpha=0.85, width=0.4)
ax.set_ylim(0, link["iterations"] * 1.15)
ax.set_ylabel("Count"); ax.set_title(f"(e) Double-vote detection ({link['accuracy_pct']}%)")
ax.axhline(link["iterations"], color=GRAY, linestyle="--", linewidth=1, alpha=0.5)

# (f) Simulation — per-vote latency vs ring size
ax = fig.add_subplot(gs[1, 2])
ax.plot(sim_voters, sim_sign_ms, "-o", color=BLUE, linewidth=1.5, markersize=3, label="Sign")
ax.plot(sim_voters, sim_verify_ms, "-s", color=RED, linewidth=1.5, markersize=3, label="Verify")
ax.set_xlabel("Voters (= ring size)"); ax.set_ylabel("ms/vote")
ax.set_title("(f) Per-vote latency vs scale"); ax.legend(fontsize=7)

save(fig, "fig7_overview.png")

print(f"\n✓ All 7 figures saved at 300 DPI.")
print(f"  Ring sizes tested: {ns.tolist()}")
print(f"  fig1_latency.png      — with scalability threshold markers")
print(f"  fig2_complexity.png    — O(n) linear fit + log-log")
print(f"  fig3_throughput.png    — ops/sec bar chart + time/op")
print(f"  fig4_size_memory.png   — signature KB + memory delta")
print(f"  fig5_linkability.png   — 100% accuracy detection")
print(f"  fig6_simulation.png    — realistic ring=voters simulation")
print(f"  fig7_overview.png      ← combined figure for paper")
