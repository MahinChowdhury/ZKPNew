"""
plot_latency.py — supplementary latency figure, generated from
results/latency_results.json (written by bench_client.mjs).

Usage (from api-server/):
    ../model/venv312/bin/python benchmark/plot_latency.py
Output: ../IEEE_Transaction_Mahin/figures/fig_supp_latency.pdf
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "model"))   # shared figure style

import matplotlib.pyplot as plt                          # noqa: E402
from matplotlib.ticker import FuncFormatter, NullFormatter   # noqa: E402

from ieee_style import PAGE_W, C, save, setup            # noqa: E402

RESULTS = HERE.parent / "results" / "latency_results.json"
CONSTRAINTS = HERE.parent / "results" / "subcircuit_constraints.json"
OUT = HERE.parent.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_supp_latency.pdf"

r = json.loads(RESULTS.read_text())
nc = json.loads(CONSTRAINTS.read_text())

setup()
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(PAGE_W, 2.35), gridspec_kw={"width_ratios": [1, 1.25]})

# (a) client phases, stacked, with 95% CI on the total
phases = [("merklePaths", "Merkle paths"), ("encryptBallot", "Ballot encryption + proofs"),
          ("witness", "Witness generation"), ("prove", "Groth16 proving")]
fills = [C["sky"], C["green"], C["orange"], C["blue"]]
hatches = ["", "////", "", ""]
modes = ["face", "iris"]
for i, mode in enumerate(modes):
    bottom = 0.0
    for (key, label), color, hatch in zip(phases, fills, hatches):
        v = r["phases"][mode][key]["mean"]
        ax1.bar(i, v, bottom=bottom, color=color, width=0.5, edgecolor="black", linewidth=0.4,
                hatch=hatch, label=label if i == 0 else None, zorder=3)
        bottom += v
    tot = r["phases"][mode]["clientTotal"]
    ax1.errorbar(i, tot["mean"], yerr=tot["ci95"], color="black", capsize=2.5, lw=0.7, zorder=4)
    ax1.text(i, tot["mean"] + tot["ci95"] + 30, rf'{tot["mean"]:,.0f} ms', ha="center", fontsize=7)
ax1.set_xticks(range(len(modes)),
               [rf'Face ({nc["face_auth (full)"]:,} constr.)', rf'Iris ({nc["iris_auth (full)"]:,} constr.)'])
ax1.tick_params(axis="x", which="both", length=0)
ax1.grid(axis="x", visible=False)
ax1.set_ylabel("Client time per ballot (ms)")
top = max(r["phases"][m]["clientTotal"]["mean"] + r["phases"][m]["clientTotal"]["ci95"] for m in modes)
ax1.set_ylim(0, 1.55 * top)
ax1.set_xlim(-0.6, 1.6)
ax1.legend(loc="upper center", ncol=2, columnspacing=0.8, handlelength=1.3)
ax1.set_title(r"(a) Voter client, per ballot", loc="left", pad=3)

# (b) scaling with electorate size
ns = sorted(int(n) for n in r["scaling"])
for key, label, color, marker, ls in (("prove", "Client Groth16 proving", C["blue"], "s", "-"),
                                      ("castVote", r"Chaincode \texttt{castVote}", C["vermillion"], "o", "--"),
                                      ("clientMerkle", "Client Merkle paths", C["black"], "^", ":")):
    ax2.plot(ns, [r["scaling"][str(n)][key]["mean"] for n in ns], color=color, marker=marker, ls=ls,
             mfc="white", mew=0.9, label=label, zorder=3)
ax2.set_xscale("log")
ax2.set_yscale("log")
fmt = FuncFormatter(lambda v, _: f"{v:g}")
ax2.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
ax2.yaxis.set_major_formatter(fmt)
ax2.yaxis.set_minor_formatter(NullFormatter())
ax2.set_xlabel(r"Enrolled voters, $N$")
ax2.set_ylabel("Time (ms)")
ax2.legend(loc="lower right")
ax2.set_title(r"(b) Scaling with the electorate (face)", loc="left", pad=3)

fig.tight_layout(w_pad=1.5)
OUT.parent.mkdir(parents=True, exist_ok=True)
save(fig, OUT)
