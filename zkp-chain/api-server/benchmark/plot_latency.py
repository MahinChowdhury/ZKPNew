"""
plot_latency.py — supplementary latency figure, generated from
results/latency_results.json (written by bench_client.mjs).

Usage (from api-server/):
    ../model/venv/bin/python benchmark/plot_latency.py
Output: ../IEEE_Transaction_Mahin/figures/fig_supp_latency.pdf
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results" / "latency_results.json"
CONSTRAINTS = HERE.parent / "results" / "subcircuit_constraints.json"
OUT = HERE.parent.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_supp_latency.pdf"

r = json.loads(RESULTS.read_text())
nc = json.loads(CONSTRAINTS.read_text())

plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.linewidth": 0.6})
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.4))

# (a) client phases, stacked, with 95% CI on the total
phases = [("merklePaths", "Merkle paths"), ("encryptBallot", "Ballot encryption"),
          ("witness", "Witness"), ("prove", "Groth16 prove")]
colors = ["#9ecae1", "#6baed6", "#3182bd", "#08519c"]
modes = ["face", "iris"]
for i, mode in enumerate(modes):
    bottom = 0.0
    for (key, label), color in zip(phases, colors):
        v = r["phases"][mode][key]["mean"]
        ax1.bar(i, v, bottom=bottom, color=color, width=0.55, label=label if i == 0 else None)
        bottom += v
    tot = r["phases"][mode]["clientTotal"]
    ax1.errorbar(i, tot["mean"], yerr=tot["ci95"], color="black", capsize=3, lw=0.8)
    ax1.text(i, tot["mean"] + 40, f'{tot["mean"]:.0f} ms', ha="center", fontsize=7)
ax1.set_xticks(range(len(modes)), [f'Face ({nc["face_auth (full)"]:,})', f'Iris ({nc["iris_auth (full)"]:,})'])
ax1.set_ylabel("Client time per ballot (ms)")
top = max(r["phases"][m]["clientTotal"]["mean"] + r["phases"][m]["clientTotal"]["ci95"] for m in modes)
ax1.set_ylim(0, 1.25 * top)
ax1.set_xlim(-0.6, 1.6)
ax1.set_title(f"(a) Voter client, snarkjs WASM ({r['runs']} runs, N={r['electorate']:,})", fontsize=8)
ax1.legend(frameon=False, fontsize=6.5, loc="upper center", ncol=2)

# (b) scaling with electorate size
ns = sorted(int(n) for n in r["scaling"])
paths = [r["scaling"][str(n)]["clientMerkle"]["mean"] for n in ns]
cast = [r["scaling"][str(n)]["castVote"]["mean"] for n in ns]
prove = [r["scaling"][str(n)]["prove"]["mean"] for n in ns]
ax2.plot(ns, prove, "s-", color="#08519c", ms=3, lw=1, label="Client Groth16 prove")
ax2.plot(ns, cast, "o-", color="#e6550d", ms=3, lw=1, label="Chaincode castVote")
ax2.plot(ns, paths, "^--", color="#636363", ms=3, lw=1, label="Client Merkle paths")
ax2.set_xscale("log")
ax2.set_yscale("log")
ax2.set_xlabel("Enrolled voters N")
ax2.set_ylabel("ms (log)")
ax2.set_title("(b) Scaling with the electorate (face)", fontsize=8)
ax2.legend(frameon=False, fontsize=6.5, loc="upper left")
ax2.grid(True, which="major", lw=0.3, alpha=0.5)

fig.tight_layout()
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, bbox_inches="tight")
print(f"wrote {OUT}")
