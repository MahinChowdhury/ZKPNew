"""
E2E Vote Casting Latency — Dual Modality Plot Generator
Architecture: ZK-SNARK (Groth16) + Merkle Tree + Nullifier
Reads e2e_results.json and outputs Figure 9 with Face vs Iris comparison.
"""
import json, os, sys, numpy as np, matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(SCRIPT_DIR, "e2e_results.json")

with open(INPUT_PATH) as f:
    data = json.load(f)

meta = data["meta"]
face = data["face"]
iris = data["iris"]

PHASE_KEYS = [
    "p1_qr_decrypt", "p2_bio_extract", "p3_cred_nullifier",
    "p4_merkle_build", "p5_snark_prove", "p6_snark_verify",
    "p7_elgamal_zkp", "p8_fabric_submit",
]

PHASE_LABELS = {
    "p1_qr_decrypt":     "P1: QR+PBKDF2+AES",
    "p2_bio_extract":    "P2: Biometric Extract",
    "p3_cred_nullifier": "P3: Nullifier Compute",
    "p4_merkle_build":   "P4: Merkle Tree",
    "p5_snark_prove":    "P5: ZK-SNARK Prove",
    "p6_snark_verify":   "P6: ZK-SNARK Verify",
    "p7_elgamal_zkp":    "P7: ElGamal+ZKP",
    "p8_fabric_submit":  "P8: Fabric Submit",
}

# Color palette per phase (warm→cool)
COLORS = ["#A8D5F5", "#6CB2E8", "#FFD166", "#06D6A0", "#E74C3C", "#F1948A", "#8E44AD", "#2C3E50"]
FACE_COLOR = "#E74C3C"
IRIS_COLOR = "#2E86C1"

# ── style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11,
    "axes.labelsize":    10,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   8,
    "savefig.dpi":       300,
    "axes.grid":         True,
    "grid.linestyle":    "--",
    "grid.alpha":        0.35,
    "axes.spines.top":   False,
    "axes.spines.right": False,
})

fig, axes = plt.subplots(2, 2, figsize=(15, 10))
fig.suptitle(
    f"Figure 9 — E2E Vote Casting Latency: Face vs. Iris ZK-SNARK Pipeline\n"
    f"(Groth16 + Merkle Tree + Nullifier, {meta['iterations']} iterations, {meta['candidates']} candidates)",
    fontsize=12, fontweight="bold"
)

# ── Panel (a): Stacked horizontal bars — Face vs Iris ─────────────────────────
ax = axes[0, 0]

face_means = [face["phases"][k]["stats"]["trimmedMean"] for k in PHASE_KEYS]
iris_means = [iris["phases"][k]["stats"]["trimmedMean"] for k in PHASE_KEYS]
labels     = [PHASE_LABELS[k] for k in PHASE_KEYS]

y_positions = [1, 0]  # Face at top, Iris at bottom
bar_data = [face_means, iris_means]
bar_labels = ["Face (Cosine ZK-SNARK)", "Iris (Hamming ZK-SNARK)"]

for yi, (y, means) in enumerate(zip(y_positions, bar_data)):
    left = 0
    for i, (mean, color) in enumerate(zip(means, COLORS)):
        bar = ax.barh(y, mean, left=left, color=color, edgecolor="white",
                      linewidth=0.5, height=0.6,
                      label=labels[i] if yi == 0 else None)
        if mean > max(sum(face_means), sum(iris_means)) * 0.04:
            ax.text(left + mean / 2, y, f"{mean:.0f}",
                    ha="center", va="center", fontsize=7,
                    color="white" if mean > 50 else "black", fontweight="bold")
        left += mean

face_total = sum(face_means)
iris_total = sum(iris_means)
ax.text(face_total + 10, 1, f"Total: {face_total:.0f}ms", va="center", fontsize=8, fontweight="bold", color=FACE_COLOR)
ax.text(iris_total + 10, 0, f"Total: {iris_total:.0f}ms", va="center", fontsize=8, fontweight="bold", color=IRIS_COLOR)

ax.set_yticks(y_positions)
ax.set_yticklabels(bar_labels, fontweight="bold")
ax.set_xlabel("Cumulative latency (ms)")
ax.set_title("(a) Stacked pipeline latency — Face vs. Iris")
ax.legend(loc="lower right", ncol=2, framealpha=0.9, fontsize=7)

# ── Panel (b): Per-phase grouped bar chart ────────────────────────────────────
ax2 = axes[0, 1]
x = np.arange(len(PHASE_KEYS))
width = 0.35

face_vals = [face["phases"][k]["stats"]["trimmedMean"] for k in PHASE_KEYS]
face_sds  = [face["phases"][k]["stats"]["trimmedSd"]   for k in PHASE_KEYS]
iris_vals = [iris["phases"][k]["stats"]["trimmedMean"] for k in PHASE_KEYS]
iris_sds  = [iris["phases"][k]["stats"]["trimmedSd"]   for k in PHASE_KEYS]

bars1 = ax2.bar(x - width/2, face_vals, width, yerr=face_sds,
                label="Face", color=FACE_COLOR, alpha=0.85, capsize=3, edgecolor="white")
bars2 = ax2.bar(x + width/2, iris_vals, width, yerr=iris_sds,
                label="Iris", color=IRIS_COLOR, alpha=0.85, capsize=3, edgecolor="white")

ax2.set_xticks(x)
ax2.set_xticklabels([PHASE_LABELS[k].split(":")[0] for k in PHASE_KEYS], rotation=45, ha="right")
ax2.set_ylabel("Latency (ms)")
ax2.set_title("(b) Per-phase comparison (trimmed mean ± σ)")
ax2.legend()

# ── Panel (c): Crypto-only breakdown (exclude mocked phases) ─────────────────
ax3 = axes[1, 0]

CRYPTO_KEYS = ["p3_cred_nullifier", "p4_merkle_build", "p5_snark_prove", "p6_snark_verify", "p7_elgamal_zkp"]
CRYPTO_LABELS = [PHASE_LABELS[k].split(": ")[1] for k in CRYPTO_KEYS]

face_crypto = [face["phases"][k]["stats"]["trimmedMean"] for k in CRYPTO_KEYS]
iris_crypto = [iris["phases"][k]["stats"]["trimmedMean"] for k in CRYPTO_KEYS]

x3 = np.arange(len(CRYPTO_KEYS))
bars3a = ax3.bar(x3 - width/2, face_crypto, width, label="Face", color=FACE_COLOR, alpha=0.85, edgecolor="white")
bars3b = ax3.bar(x3 + width/2, iris_crypto, width, label="Iris", color=IRIS_COLOR, alpha=0.85, edgecolor="white")

# Value labels
for bar, val in zip(bars3a, face_crypto):
    if val > 0.5:
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f"{val:.0f}", ha="center", fontsize=7, color=FACE_COLOR, fontweight="bold")
for bar, val in zip(bars3b, iris_crypto):
    if val > 0.5:
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f"{val:.0f}", ha="center", fontsize=7, color=IRIS_COLOR, fontweight="bold")

# Speedup annotations on SNARK prove
face_prove = face["phases"]["p5_snark_prove"]["stats"]["trimmedMean"]
iris_prove = iris["phases"]["p5_snark_prove"]["stats"]["trimmedMean"]
if iris_prove > 0:
    speedup = face_prove / iris_prove
    ax3.annotate(
        f"{speedup:.1f}× faster",
        xy=(2 + width/2, iris_prove),
        xytext=(3.5, max(face_crypto) * 0.8),
        fontsize=9, fontweight="bold", color="#27AE60",
        arrowprops=dict(arrowstyle="->", color="#27AE60", lw=1.5),
        ha="center",
    )

ax3.set_xticks(x3)
ax3.set_xticklabels(CRYPTO_LABELS, rotation=30, ha="right")
ax3.set_ylabel("Latency (ms)")
ax3.set_title("(c) Cryptographic phases only (real computation)")
ax3.legend()

# ── Panel (d): Pie chart showing phase distribution  ──────────────────────────
ax4 = axes[1, 1]

# Show pie for IRIS pipeline (the proposed one)
iris_all = [iris["phases"][k]["stats"]["trimmedMean"] for k in PHASE_KEYS]
total_iris = sum(iris_all)

# Combine small slices
threshold = total_iris * 0.02
pie_vals = []
pie_labels_list = []
pie_colors = []
other = 0
for val, label, color in zip(iris_all, [PHASE_LABELS[k] for k in PHASE_KEYS], COLORS):
    if val < threshold:
        other += val
    else:
        pie_vals.append(val)
        pie_labels_list.append(label)
        pie_colors.append(color)
if other > 0:
    pie_vals.append(other)
    pie_labels_list.append("Other")
    pie_colors.append("#CCCCCC")

wedges, texts, autotexts = ax4.pie(
    pie_vals, labels=pie_labels_list, autopct="%1.1f%%",
    colors=pie_colors, startangle=90,
    textprops={"fontsize": 8},
    pctdistance=0.75,
    wedgeprops=dict(edgecolor="white", linewidth=1.5),
)
for t in autotexts:
    t.set_fontsize(7)
    t.set_fontweight("bold")
ax4.set_title(f"(d) Iris pipeline phase distribution\n(Total ≈ {total_iris:.0f}ms)")

fig.tight_layout(rect=[0, 0, 1, 0.93])
out_path = os.path.join(SCRIPT_DIR, "fig9_e2e_latency.png")
fig.savefig(out_path, bbox_inches="tight", dpi=300)
plt.close(fig)
print(f"[+] Saved {out_path}")

# ── Table image: E2E Latency Face vs Iris ──────────────────────────────────────
fig_tbl, ax_tbl = plt.subplots(figsize=(14, 5))
ax_tbl.axis("off")

# Build table data
col_labels = ["Phase", "Description", "Face (ms)", "Iris (ms)", "Speedup"]
table_data = []
cell_colors = []
header_color = "#2C3E50"
row_even = "#F8F9FA"
row_odd  = "#FFFFFF"
highlight = "#E8F8F5"

for idx, key in enumerate(PHASE_KEYS):
    f_st = face["phases"][key]["stats"]
    i_st = iris["phases"][key]["stats"]
    label = PHASE_LABELS[key]
    name = label.split(":")[0]
    desc = label.split(": ")[1] if ": " in label else label
    ratio = f_st["trimmedMean"] / i_st["trimmedMean"] if i_st["trimmedMean"] > 0 else 0
    sim = " *" if key in ("p2_bio_extract", "p8_fabric_submit") and not meta["live_fabric"] else ""
    table_data.append([
        name,
        f"{desc}{sim}",
        f"{f_st['trimmedMean']:.1f} ± {f_st['trimmedSd']:.1f}",
        f"{i_st['trimmedMean']:.1f} ± {i_st['trimmedSd']:.1f}",
        f"{ratio:.2f}×",
    ])
    bg = highlight if key == "p5_snark_prove" else (row_even if idx % 2 == 0 else row_odd)
    cell_colors.append([bg] * 5)

# Total row
table_data.append([
    "Total", "—",
    f"{data['comparison']['total_face_ms']:.1f}",
    f"{data['comparison']['total_iris_ms']:.1f}",
    f"{data['comparison']['speedup_ratio']:.2f}×",
])
cell_colors.append(["#D5F5E3"] * 5)

tbl = ax_tbl.table(
    cellText=table_data,
    colLabels=col_labels,
    cellColours=cell_colors,
    colColours=[header_color] * 5,
    cellLoc="center",
    loc="center",
)
tbl.auto_set_font_size(False)
tbl.set_fontsize(9)
tbl.scale(1, 1.6)

# Style header
for (row, col), cell in tbl.get_celld().items():
    if row == 0:
        cell.set_text_props(color="white", fontweight="bold")
        cell.set_edgecolor("white")
    else:
        cell.set_edgecolor("#E0E0E0")
    if col == 0 or col == 1:
        cell.set_text_props(ha="left")

ax_tbl.set_title(
    "Table: E2E Vote Casting Latency — Face vs. Iris Pipeline\n"
    f"(ZK-SNARK Groth16 + Merkle Tree + Nullifier, {meta['iterations']} iterations)",
    fontsize=11, fontweight="bold", pad=20,
)

if not meta["live_fabric"]:
    ax_tbl.text(0.5, -0.02, "* P2/P8 are simulated — re-run with --live for real network latency",
                transform=ax_tbl.transAxes, ha="center", fontsize=8, style="italic", color="#888")

tbl_path = os.path.join(SCRIPT_DIR, "fig10_e2e_table.png")
fig_tbl.savefig(tbl_path, bbox_inches="tight", dpi=300, facecolor="white")
plt.close(fig_tbl)
print(f"[+] Saved {tbl_path}")
