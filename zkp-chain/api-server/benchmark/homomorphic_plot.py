"""
Homomorphic Encryption Plot Generator
Reads homomorphic_results.json and outputs a 2-panel publication-ready figure.
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

with open("homomorphic_results.json") as f:
    data = json.load(f)

base = data["base_latency"]
bsgs = data["bsgs_latency"]
zkp  = data["zkp_latency"]
sizes = data["sizes"]

# Global style (matching LRS plots for consistency)
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11,
    "axes.labelsize":    10,
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
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
PURPLE = "#7C3AED"
GRAY   = "#6B7280"

fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
fig.suptitle("Figure 8: Exponential ElGamal Homomorphic Tallying Performance", fontsize=11, fontweight="bold")

# ═══════════════════════════════════════════════════════════════════════════════
# Panel (a) — Base Operations Latency
# ═══════════════════════════════════════════════════════════════════════════════

ax = axes[0]
ops = [
    "Encrypt\n(1 vote)",
    "Decrypt\n(to curve pt)",
    "Homomorphic\nAdd",
    "ZKP\nProve",
    "ZKP\nVerify"
]
means = [
    base["encrypt"]["mean"],
    base["decrypt_to_point"]["mean"],
    base["homomorphic_add"]["mean"],
    zkp["prove"]["mean"],
    zkp["verify"]["mean"]
]
sds = [
    base["encrypt"]["sd"],
    base["decrypt_to_point"]["sd"],
    base["homomorphic_add"]["sd"],
    zkp["prove"]["sd"],
    zkp["verify"]["sd"]
]
colors = [BLUE, GRAY, GREEN, PURPLE, RED]

x = np.arange(len(ops))
bars = ax.bar(x, means, yerr=sds, color=colors, alpha=0.85, capsize=5, width=0.5)

ax.set_xticks(x)
ax.set_xticklabels(ops)
ax.set_ylabel("Latency (ms)")
ax.set_title("(a) Cryptographic operations latency")

# Annotate values
for bar, m in zip(bars, means):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, f"{m:.2f}ms", ha="center", fontsize=8)

# ═══════════════════════════════════════════════════════════════════════════════
# Panel (b) — BSGS Time vs N
# ═══════════════════════════════════════════════════════════════════════════════

ax = axes[1]
ns = np.array([d["max_voters"] for d in bsgs])
bsgs_means = np.array([d["stats"]["mean"] for d in bsgs])
bsgs_sds = np.array([d["stats"]["sd"] for d in bsgs])

ax.plot(ns, bsgs_means, "-o", color=BLUE, linewidth=1.8, markersize=5, label="Measured BSGS Time")
ax.fill_between(ns, bsgs_means - bsgs_sds, bsgs_means + bsgs_sds, color=BLUE, alpha=0.1)

# Fit O(sqrt(N)) curve
fit_x = np.linspace(ns[0], ns[-1], 200)
sqrt_ns = np.sqrt(ns)
c = np.polyfit(sqrt_ns, bsgs_means, 1)
fit_y = np.polyval(c, np.sqrt(fit_x))
ax.plot(fit_x, fit_y, "--", color=GRAY, linewidth=1.2, label=f"Fit: {c[0]:.4f}√n + {c[1]:.2f}")

ax.set_xscale("log")
ax.set_xlabel("Maximum expected votes (N)")
ax.set_ylabel("Solve time (ms)")
ax.set_title("(b) Baby-step Giant-step discrete log recovery")
ax.legend()

# ═══════════════════════════════════════════════════════════════════════════════
# Panel (c) — Vector Latency vs Candidate Count
# ═══════════════════════════════════════════════════════════════════════════════

ax1 = axes[2]
vec_data = data.get("vector_latency", [])
if vec_data:
    candidates = np.array([d["candidates"] for d in vec_data])
    client_means = np.array([d["encrypt_and_prove"]["mean"] for d in vec_data])
    client_sds = np.array([d["encrypt_and_prove"]["sd"] for d in vec_data])
    server_means = np.array([d["homomorphic_add"]["mean"] for d in vec_data])
    server_sds = np.array([d["homomorphic_add"]["sd"] for d in vec_data])
    
    color1 = BLUE
    ax1.set_xlabel("Number of Candidates on Ballot (C)")
    ax1.set_ylabel("Client latency (ms) [Encrypt + ZKP]", color=color1)
    line1 = ax1.errorbar(candidates, client_means, yerr=client_sds, fmt="o-", color=color1, linewidth=1.8, markersize=5, capsize=3, label="Client Cost O(C)")
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_xticks(candidates)
    
    ax2 = ax1.twinx()
    color2 = GREEN
    ax2.set_ylabel("Server latency (ms) [Homomorphic Add]", color=color2)
    line2 = ax2.errorbar(candidates, server_means, yerr=server_sds, fmt="s--", color=color2, linewidth=1.8, markersize=5, capsize=3, label="Server Cost O(C)")
    ax2.tick_params(axis='y', labelcolor=color2)
    
    ax1.set_title("(c) Vector voting scalability O(C)")
    
    lines = [line1, line2]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left")

# ═══════════════════════════════════════════════════════════════════════════════

fig.tight_layout()
fig.savefig("fig8_homomorphic.png", bbox_inches="tight", dpi=300)
plt.close(fig)

print("[+] Saved fig8_homomorphic.png")

# Also print the sizes so they can be included in the paper's text
print(f"Ciphertext Size: {sizes['ciphertext_json_bytes']} bytes (JSON) / {sizes['ciphertext_compact_bytes']} bytes (Compact)")
print(f"ZKP Proof Size: {sizes['zkp_proof_json_bytes']} bytes (JSON) / {sizes['zkp_proof_compact_bytes']} bytes (Compact)")
