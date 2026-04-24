"""
E2E Scalability Plot Generator — Dual Modality
Architecture: ZK-SNARK (Groth16) + Merkle Tree + Nullifier
Reads e2e_scalability_results.json and generates a 4-panel figure.
"""
import json, os, numpy as np, matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(SCRIPT_DIR, "e2e_scalability_results.json")

with open(INPUT_PATH) as f:
    data = json.load(f)

meta     = data["meta"]
voter_sw = data["dim1_voter_sweep"]
cand_sw  = data["dim2_candidate_sweep"]

plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11, "axes.labelsize": 10,
    "xtick.labelsize":   9,  "ytick.labelsize": 9,
    "legend.fontsize":   9,  "savefig.dpi": 300,
    "axes.grid":         True, "grid.linestyle": "--", "grid.alpha": 0.4,
    "axes.spines.top":   False, "axes.spines.right": False,
})

FACE_COLOR  = "#E74C3C"
IRIS_COLOR  = "#2E86C1"
GREEN       = "#27AE60"
PURPLE      = "#8E44AD"
ORANGE      = "#F39C12"
GRAY        = "#6B7280"

fig = plt.figure(figsize=(14, 10))
gs  = GridSpec(2, 2, figure=fig, hspace=0.42, wspace=0.35)

fig.suptitle(
    f"ZK-SNARK Scalability Analysis — Face vs. Iris Pipeline\n"
    f"(Groth16 + Poseidon Merkle Tree, {meta['iterations']} iterations per config)",
    fontsize=12, fontweight="bold"
)

# ── Panel (a): SNARK Prove Time vs Voter Count ────────────────────────────────
ax1 = fig.add_subplot(gs[0, 0])
ns = [r["voters"] for r in voter_sw]

face_prove = [r["face"]["snark_prove"]["trimmedMean"] for r in voter_sw]
face_prove_sd = [r["face"]["snark_prove"]["trimmedSd"] for r in voter_sw]
iris_prove = [r["iris"]["snark_prove"]["trimmedMean"] for r in voter_sw]
iris_prove_sd = [r["iris"]["snark_prove"]["trimmedSd"] for r in voter_sw]

ax1.errorbar(ns, face_prove, yerr=face_prove_sd, fmt="o-", color=FACE_COLOR,
             lw=2, capsize=3, ms=6, label="Face SNARK Prove")
ax1.errorbar(ns, iris_prove, yerr=iris_prove_sd, fmt="s-", color=IRIS_COLOR,
             lw=2, capsize=3, ms=6, label="Iris SNARK Prove")

# Annotate speedup at largest voter count
if iris_prove[-1] > 0:
    speedup = face_prove[-1] / iris_prove[-1]
    ax1.annotate(
        f"{speedup:.1f}× faster",
        xy=(ns[-1], iris_prove[-1]),
        xytext=(ns[-2], (face_prove[-1] + iris_prove[-1]) / 2),
        fontsize=10, fontweight="bold", color=GREEN,
        arrowprops=dict(arrowstyle="->", color=GREEN, lw=1.5),
        ha="center",
    )

ax1.set_xlabel("Number of registered voters (Merkle tree size)")
ax1.set_ylabel("SNARK Prove Time (ms)")
ax1.set_title("(a) ZK-SNARK Proving Time vs. Voter Pool Size")
ax1.legend()

# ── Panel (b): Merkle Tree Build Time vs Voter Count ──────────────────────────
ax2 = fig.add_subplot(gs[0, 1])

face_merkle = [r["face"]["merkle_build"]["trimmedMean"] for r in voter_sw]
face_merkle_sd = [r["face"]["merkle_build"]["trimmedSd"] for r in voter_sw]
iris_merkle = [r["iris"]["merkle_build"]["trimmedMean"] for r in voter_sw]
iris_merkle_sd = [r["iris"]["merkle_build"]["trimmedSd"] for r in voter_sw]
face_total = [r["face"]["total_crypto"]["trimmedMean"] for r in voter_sw]
iris_total = [r["iris"]["total_crypto"]["trimmedMean"] for r in voter_sw]

ax2.errorbar(ns, face_merkle, yerr=face_merkle_sd, fmt="o-", color=FACE_COLOR,
             lw=2, capsize=3, ms=5, label="Face Merkle Build")
ax2.errorbar(ns, iris_merkle, yerr=iris_merkle_sd, fmt="s-", color=IRIS_COLOR,
             lw=2, capsize=3, ms=5, label="Iris Merkle Build")
ax2.plot(ns, face_total, "^--", color=FACE_COLOR, lw=1.2, ms=5, alpha=0.5, label="Face Total Crypto")
ax2.plot(ns, iris_total, "v--", color=IRIS_COLOR, lw=1.2, ms=5, alpha=0.5, label="Iris Total Crypto")

ax2.set_xlabel("Number of registered voters")
ax2.set_ylabel("Latency (ms)")
ax2.set_title("(b) Poseidon Merkle Tree Build + Total Crypto")
ax2.legend(fontsize=8)

# ── Panel (c): Stacked phase breakdown at each voter count (Face vs Iris) ─────
ax3 = fig.add_subplot(gs[1, 0])

x = np.arange(len(ns))
bar_w = 0.35

# Face stacked
face_mk = [r["face"]["merkle_build"]["trimmedMean"] for r in voter_sw]
face_pr = [r["face"]["snark_prove"]["trimmedMean"]  for r in voter_sw]
face_vr = [r["face"]["snark_verify"]["trimmedMean"] for r in voter_sw]

ax3.bar(x - bar_w/2, face_mk, bar_w, color=FACE_COLOR, alpha=0.4, label="Face: Merkle")
ax3.bar(x - bar_w/2, face_pr, bar_w, bottom=face_mk, color=FACE_COLOR, alpha=0.7, label="Face: SNARK Prove")
ax3.bar(x - bar_w/2, face_vr, bar_w,
        bottom=[a + b for a, b in zip(face_mk, face_pr)],
        color=FACE_COLOR, alpha=1.0, label="Face: SNARK Verify")

# Iris stacked
iris_mk = [r["iris"]["merkle_build"]["trimmedMean"] for r in voter_sw]
iris_pr = [r["iris"]["snark_prove"]["trimmedMean"]  for r in voter_sw]
iris_vr = [r["iris"]["snark_verify"]["trimmedMean"] for r in voter_sw]

ax3.bar(x + bar_w/2, iris_mk, bar_w, color=IRIS_COLOR, alpha=0.4, label="Iris: Merkle")
ax3.bar(x + bar_w/2, iris_pr, bar_w, bottom=iris_mk, color=IRIS_COLOR, alpha=0.7, label="Iris: SNARK Prove")
ax3.bar(x + bar_w/2, iris_vr, bar_w,
        bottom=[a + b for a, b in zip(iris_mk, iris_pr)],
        color=IRIS_COLOR, alpha=1.0, label="Iris: SNARK Verify")

ax3.set_xticks(x)
ax3.set_xticklabels(ns)
ax3.set_xlabel("Number of voters")
ax3.set_ylabel("Cumulative crypto latency (ms)")
ax3.set_title("(c) Phase breakdown vs. voter count")
ax3.legend(fontsize=7, ncol=2)

# ── Panel (d): ElGamal+ZKP vs Candidate Count ────────────────────────────────
ax4 = fig.add_subplot(gs[1, 1])

cs = [c["candidates"] for c in cand_sw]
enc_mean = [c["elgamal_zkp"]["trimmedMean"] for c in cand_sw]
enc_sd   = [c["elgamal_zkp"]["trimmedSd"]   for c in cand_sw]

ax4.errorbar(cs, enc_mean, yerr=enc_sd, fmt="o-", color=PURPLE, lw=2, capsize=3, ms=6,
             label="Encrypt + Vote Validity ZKP")

# Linear fit
coeff = np.polyfit(cs, enc_mean, 1)
fit_x = np.linspace(cs[0], cs[-1], 100)
ax4.plot(fit_x, np.polyval(coeff, fit_x), ":", color=PURPLE, lw=1.2, alpha=0.7,
         label=f"Linear fit: {coeff[0]:.1f}C + {coeff[1]:.1f}")

# Per-candidate cost annotation
per_cand = coeff[0]
ax4.text(
    0.55, 0.90,
    f"≈ {per_cand:.1f} ms per candidate\n(ElGamal encrypt + Chaum-Pedersen ZKP)",
    transform=ax4.transAxes,
    fontsize=9, fontweight="bold", color="white",
    bbox=dict(boxstyle="round,pad=0.4", facecolor=PURPLE, alpha=0.85, edgecolor="none"),
    ha="center", va="top",
)

ax4.set_xlabel("Number of candidates (C)")
ax4.set_ylabel("ElGamal + ZKP latency (ms)")
ax4.set_title("(d) ElGamal+ZKP scalability — O(C)")
ax4.set_xticks(cs)
ax4.legend(fontsize=8)

fig.savefig(os.path.join(SCRIPT_DIR, "fig9_e2e_scalability.png"), bbox_inches="tight", dpi=300)
plt.close(fig)
print(f"[+] Saved fig9_e2e_scalability.png")

# ── Table image 1: SNARK Latency vs Voter Count ──────────────────────────────
fig_t1, ax_t1 = plt.subplots(figsize=(14, 4.5))
ax_t1.axis("off")

col_labels_1 = ["Voters", "Face Prove (ms)", "Iris Prove (ms)", "Face Merkle (ms)", "Iris Merkle (ms)", "Speedup"]
table_data_1 = []
cell_colors_1 = []
header_color = "#2C3E50"
row_even = "#F8F9FA"
row_odd  = "#FFFFFF"

for idx, r in enumerate(voter_sw):
    fp = r["face"]["snark_prove"]
    ip = r["iris"]["snark_prove"]
    fm = r["face"]["merkle_build"]
    im = r["iris"]["merkle_build"]
    speedup = fp["trimmedMean"] / ip["trimmedMean"] if ip["trimmedMean"] > 0 else 0
    table_data_1.append([
        str(r["voters"]),
        f"{fp['trimmedMean']:.1f} ± {fp['trimmedSd']:.1f}",
        f"{ip['trimmedMean']:.1f} ± {ip['trimmedSd']:.1f}",
        f"{fm['trimmedMean']:.1f}",
        f"{im['trimmedMean']:.1f}",
        f"{speedup:.2f}×",
    ])
    bg = row_even if idx % 2 == 0 else row_odd
    cell_colors_1.append([bg] * 6)

tbl1 = ax_t1.table(
    cellText=table_data_1,
    colLabels=col_labels_1,
    cellColours=cell_colors_1,
    colColours=[header_color] * 6,
    cellLoc="center",
    loc="center",
)
tbl1.auto_set_font_size(False)
tbl1.set_fontsize(9)
tbl1.scale(1, 1.6)

for (row, col), cell in tbl1.get_celld().items():
    if row == 0:
        cell.set_text_props(color="white", fontweight="bold")
        cell.set_edgecolor("white")
    else:
        cell.set_edgecolor("#E0E0E0")

ax_t1.set_title(
    "Table: ZK-SNARK Proving Time vs. Merkle Tree Size (Voters)\n"
    f"({meta['iterations']} iterations per config)",
    fontsize=11, fontweight="bold", pad=20,
)

t1_path = os.path.join(SCRIPT_DIR, "fig10_scalability_table.png")
fig_t1.savefig(t1_path, bbox_inches="tight", dpi=300, facecolor="white")
plt.close(fig_t1)
print(f"[+] Saved {t1_path}")

# ── Table image 2: ElGamal+ZKP vs Candidate Count ────────────────────────────
fig_t2, ax_t2 = plt.subplots(figsize=(8, 3.5))
ax_t2.axis("off")

col_labels_2 = ["Candidates", "Encrypt+ZKP (ms)", "Per-Candidate (ms)"]
table_data_2 = []
cell_colors_2 = []

for idx, c in enumerate(cand_sw):
    eg = c["elgamal_zkp"]
    per_c = eg["trimmedMean"] / c["candidates"]
    table_data_2.append([
        str(c["candidates"]),
        f"{eg['trimmedMean']:.1f} ± {eg['trimmedSd']:.1f}",
        f"{per_c:.1f}",
    ])
    bg = row_even if idx % 2 == 0 else row_odd
    cell_colors_2.append([bg] * 3)

tbl2 = ax_t2.table(
    cellText=table_data_2,
    colLabels=col_labels_2,
    cellColours=cell_colors_2,
    colColours=[header_color] * 3,
    cellLoc="center",
    loc="center",
)
tbl2.auto_set_font_size(False)
tbl2.set_fontsize(9)
tbl2.scale(1, 1.6)

for (row, col), cell in tbl2.get_celld().items():
    if row == 0:
        cell.set_text_props(color="white", fontweight="bold")
        cell.set_edgecolor("white")
    else:
        cell.set_edgecolor("#E0E0E0")

ax_t2.set_title(
    "Table: ElGamal + Vote Validity ZKP vs. Candidate Count\n"
    f"({meta['iterations']} iterations per config)",
    fontsize=11, fontweight="bold", pad=20,
)

t2_path = os.path.join(SCRIPT_DIR, "fig11_elgamal_table.png")
fig_t2.savefig(t2_path, bbox_inches="tight", dpi=300, facecolor="white")
plt.close(fig_t2)
print(f"[+] Saved {t2_path}")

