"""
E2E Vote Casting Latency Plot Generator — Category C
Reads e2e_results.json and outputs a stacked bar + phase breakdown table for the paper.
"""
import json, sys, numpy as np, matplotlib.pyplot as plt

# ── load ──────────────────────────────────────────────────────────────────────
with open("e2e_results.json") as f:
    data = json.load(f)

meta   = data["meta"]
phases = data["phases"]

PHASE_LABELS = {
    "p1_qr_decrypt":     "P1: QR+PBKDF2+AES",
    "p2_face_embed":     "P2: Face Embedding",
    "p3_face_compare":   "P3: Cosine Match",
    "p4_key_derive":     "P4: Key Derivation",
    "p5_lrs_sign":       "P5: LRS Sign",
    "p6_lrs_verify":     "P6: LRS Verify",
    "p7_elgamal_vector": "P7: ElGamal+ZKP",
    "p8_fabric_submit":  "P8: Fabric Submit",
}

# Palette: warm-to-cool from light to heavy phases
COLORS = ["#A8D5F5", "#6CB2E8", "#60C070", "#F5E16B", "#F5A623", "#E85858", "#8E44AD", "#2C3E50"]

means  = [phases[k]["stats"]["mean"] for k in phases]
sds    = [phases[k]["stats"]["sd"]   for k in phases]
labels = [PHASE_LABELS[k]            for k in phases]
total  = sum(means)

# ── style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family":     "serif",
    "font.serif":      ["Times New Roman","DejaVu Serif"],
    "axes.titlesize":  11,
    "axes.labelsize":  10,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "savefig.dpi":     300,
    "axes.grid":       True,
    "grid.linestyle":  "--",
    "grid.alpha":      0.35,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), gridspec_kw={"width_ratios": [1.2, 1]})
fig.suptitle("Figure 9 — End-to-End Vote Casting Latency Breakdown "
             f"(ring_size={meta['ring_size']}, candidates={meta['candidates']})",
             fontsize=11, fontweight="bold")

# ── Panel (a): stacked horizontal bar ─────────────────────────────────────────
ax = axes[0]
y = 0
LEFT = 0
for i, (key, label, mean, color) in enumerate(zip(phases, labels, means, COLORS)):
    bar = ax.barh(y, mean, left=LEFT, color=color, edgecolor="white", linewidth=0.5, label=label)
    # Annotate inside bar if wide enough
    if mean > 12:
        ax.text(LEFT + mean / 2, y, f"{mean:.0f}ms", ha="center", va="center",
                fontsize=7.5, color="white" if mean > 60 else "black", fontweight="bold")
    LEFT += mean

ax.barh(y, 0, left=0, color="none")  # dummy for total
ax.set_xlim(0, total * 1.08)
ax.set_yticks([0])
ax.set_yticklabels(["Vote Cast"])
ax.set_xlabel("Cumulative latency (ms)")
ax.set_title("(a) Stacked pipeline latency breakdown")

# Total annotation
ax.annotate(f"Total ≈ {total:.0f} ms",
            xy=(total, 0), xytext=(15, 12),
            textcoords="offset points", fontsize=9,
            arrowprops=dict(arrowstyle="->", color="gray"))

ax.legend(loc="lower right", ncol=2, framealpha=0.9, fontsize=8)

# ── Panel (b): per-phase bar chart with error bars ────────────────────────────
ax2 = axes[1]
y_pos = np.arange(len(labels))[::-1]   # reverse so P1 at top

bars = ax2.barh(y_pos, means, xerr=sds, color=COLORS, alpha=0.88,
                capsize=4, edgecolor="white", linewidth=0.5)

# Annotate with mean ± sd
for bar, m, s in zip(bars, means, sds):
    ax2.text(m + max(sds) * 0.1, bar.get_y() + bar.get_height() / 2,
             f"{m:.1f} ±{s:.1f}", va="center", fontsize=7.5)

ax2.set_yticks(y_pos)
ax2.set_yticklabels(labels[::-1])
ax2.set_xlabel("Latency (ms)")
ax2.set_title("(b) Per-phase breakdown (mean ± SD)")

live_note = "" if meta["live_fabric"] else "\n* P2 & P8 are simulated (see text)"
ax2.set_xlabel(f"Latency (ms){live_note}")

fig.tight_layout()
fig.savefig("fig9_e2e_latency.png", bbox_inches="tight", dpi=300)
plt.close(fig)

print("[+] Saved fig9_e2e_latency.png")

# ── Print LaTeX table for paper ────────────────────────────────────────────────
print("\n% === LaTeX Table (paste into paper) ===")
print("\\begin{tabular}{llrrr}")
print("\\toprule")
print("Phase & Description & Mean (ms) & ±SD & P95 \\\\")
print("\\midrule")
for key, label in PHASE_LABELS.items():
    st = phases[key]["stats"]
    simulated = "*" if key in ("p2_face_embed", "p8_fabric_submit") and not meta["live_fabric"] else ""
    desc = label.replace("P1: ","").replace("P2: ","").replace("P3: ","").replace(
           "P4: ","").replace("P5: ","").replace("P6: ","").replace("P7: ","").replace("P8: ","")
    name = label.split(":")[0]
    print(f"{name} & {desc}{simulated} & {st['mean']:.1f} & {st['sd']:.1f} & {st['p95']:.1f} \\\\")
print("\\midrule")
print(f"Total & --- & {total:.1f} & --- & --- \\\\")
print("\\bottomrule")
print("\\end{tabular}")
if not meta["live_fabric"]:
    print("% *P2/P8 simulated (see footnote); re-run with --live for real numbers")
