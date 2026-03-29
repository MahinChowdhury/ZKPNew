"""
E2E Scalability Plot Generator — Q1 Journal
Reads e2e_scalability_results.json and generates Figure 9 (4 panels).
"""
import json, numpy as np, matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

with open("e2e_scalability_results.json") as f:
    data = json.load(f)

meta      = data["meta"]
bio       = data["biometric_baseline"]
ring_sw   = data["dim1_ring_sweep"]
cand_sw   = data["dim2_candidate_sweep"]
tps_sw    = data["dim3_tps_sweep"]

plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "axes.titlesize":    11, "axes.labelsize": 10,
    "xtick.labelsize":   9,  "ytick.labelsize": 9,
    "legend.fontsize":   9,  "savefig.dpi": 300,
    "axes.grid":         True, "grid.linestyle": "--", "grid.alpha": 0.4,
    "axes.spines.top":   False, "axes.spines.right": False,
})

BLUE   = "#2563EB"; RED = "#DC2626"; GREEN = "#16A34A"
PURPLE = "#7C3AED"; GRAY = "#6B7280"; ORANGE = "#F59E0B"

fig = plt.figure(figsize=(14, 10))
gs  = GridSpec(2, 2, figure=fig, hspace=0.42, wspace=0.35)

fig.suptitle(
    f"Figure 9 — ZKP E2E Vote Casting Scalability Analysis\n"
    f"(Biometric baseline: embed={bio['face_embed']['mean']:.0f}ms, compare={bio['face_compare']['mean']:.0f}ms)",
    fontsize=12, fontweight="bold"
)

# ── Panel (a): LRS Sign/Verify vs ring size ────────────────────────────────────
ax1 = fig.add_subplot(gs[0, 0])
ns         = [r["ring_size"]                for r in ring_sw]
sign_mean  = [r["p6_lrs_sign"]["mean"]      for r in ring_sw]
sign_sd    = [r["p6_lrs_sign"]["sd"]        for r in ring_sw]
verify_mean= [r["p7_lrs_verify"]["mean"]    for r in ring_sw]
verify_sd  = [r["p7_lrs_verify"]["sd"]      for r in ring_sw]
total_mean = [r["total_crypto_mean"]        for r in ring_sw]

ax1.errorbar(ns, sign_mean,   yerr=sign_sd,   fmt="o-", color=BLUE,   lw=2, capsize=3, ms=5, label="LRS Sign")
ax1.errorbar(ns, verify_mean, yerr=verify_sd, fmt="s-", color=RED,    lw=2, capsize=3, ms=5, label="LRS Verify")
ax1.plot    (ns, total_mean,              "^--", color=GRAY,   lw=1.5, ms=5, label="Total Crypto")

# O(n) reference line
c_fit = np.polyfit(ns, sign_mean, 1)
fit_x = np.linspace(ns[0], ns[-1], 100)
ax1.plot(fit_x, np.polyval(c_fit, fit_x), ":", color=BLUE, lw=1.2, alpha=0.7,
         label=f"O(n) fit: {c_fit[0]:.2f}n+{c_fit[1]:.1f}")

ax1.set_xscale("log", base=2)
ax1.set_xlabel("Ring size (n)")
ax1.set_ylabel("Latency (ms)")
ax1.set_title("(a) LRS Scalability — O(n) complexity")
ax1.set_xticks(ns)
ax1.get_xaxis().set_major_formatter(plt.ScalarFormatter())
ax1.legend(fontsize=8)

# ── Panel (b): ElGamal+ZKP vs candidate count ─────────────────────────────────
ax2 = fig.add_subplot(gs[0, 1])
cs          = [c["candidates"]               for c in cand_sw]
enc_mean    = [c["elgamal_zkp"]["mean"]      for c in cand_sw]
enc_sd      = [c["elgamal_zkp"]["sd"]        for c in cand_sw]
total_c     = [c["total_client_mean"]        for c in cand_sw]
total_c_sd  = [c["total_client_sd"]          for c in cand_sw]

ax2.errorbar(cs, enc_mean, yerr=enc_sd, fmt="o-", color=PURPLE, lw=2, capsize=3, ms=5, label="Encrypt+ZKP O(C)")
ax2.errorbar(cs, total_c,  yerr=total_c_sd, fmt="s--", color=ORANGE, lw=2, capsize=3, ms=5, label="Total Client Cost")

# Linear fit annotation
c2_fit = np.polyfit(cs, enc_mean, 1)
fit_x2 = np.linspace(cs[0], cs[-1], 100)
ax2.plot(fit_x2, np.polyval(c2_fit, fit_x2), ":", color=PURPLE, lw=1.2, alpha=0.7,
         label=f"Fit: {c2_fit[0]:.1f}C+{c2_fit[1]:.1f}")

ax2.set_xlabel("Number of candidates (C)")
ax2.set_ylabel("Latency (ms)")
ax2.set_title("(b) ElGamal+ZKP — O(C) complexity")
ax2.set_xticks(cs)
ax2.legend(fontsize=8)

# ── Panel (c): Stacked phase costs at each ring size ──────────────────────────
ax3 = fig.add_subplot(gs[1, 0])
qr_means   = [r["p1_qr_decrypt"]["mean"]  for r in ring_sw]
kd_means   = [r["p4_key_derive"]["mean"]  for r in ring_sw]
enc_means_r= [r["p8_elgamal_zkp"]["mean"] for r in ring_sw]

bar_w = 0.35
x = np.arange(len(ns))
b1 = ax3.bar(x, qr_means,    bar_w,                         color="#A8D5F5", label="QR+PBKDF2")
b2 = ax3.bar(x, kd_means,    bar_w, bottom=qr_means,        color="#60C070", label="Key Derivation")
b3 = ax3.bar(x, sign_mean,   bar_w,
             bottom=[a+b for a,b in zip(qr_means, kd_means)],
             color=BLUE, label="LRS Sign")
b4 = ax3.bar(x, verify_mean, bar_w,
             bottom=[a+b+c for a,b,c in zip(qr_means, kd_means, sign_mean)],
             color=RED, label="LRS Verify")
b5 = ax3.bar(x, enc_means_r, bar_w,
             bottom=[a+b+c+d for a,b,c,d in zip(qr_means, kd_means, sign_mean, verify_mean)],
             color=PURPLE, label="ElGamal+ZKP")

ax3.set_xlabel("Ring size (n)")
ax3.set_ylabel("Cumulative crypto latency (ms)")
ax3.set_title("(c) Phase breakdown vs ring size\n(Biometric + Fabric not shown)")
ax3.set_xticks(x); ax3.set_xticklabels(ns)
ax3.legend(fontsize=7, ncol=2)

# ── Panel (d): Fabric TPS vs concurrency ──────────────────────────────────────
ax4 = fig.add_subplot(gs[1, 1])
conc          = [t["concurrency"]               for t in tps_sw]
tps_m         = [t["tps"]["mean"]               for t in tps_sw]
tps_sd        = [t["tps"]["sd"]                 for t in tps_sw]
lat_m         = [t["submit_latency"]["mean"]     for t in tps_sw]
lat_sd        = [t["submit_latency"]["sd"]       for t in tps_sw]

ax4_twin = ax4.twinx()
l1 = ax4.errorbar(conc, tps_m, yerr=tps_sd,  fmt="o-", color=GREEN,  lw=2, capsize=3, ms=6, label="TPS")
l2 = ax4_twin.errorbar(conc, lat_m, yerr=lat_sd, fmt="s--", color=ORANGE, lw=2, capsize=3, ms=6, label="Submit Latency")

ax4.set_xlabel("Concurrent voters")
ax4.set_ylabel("Transactions per second (TPS)", color=GREEN)
ax4_twin.set_ylabel("Submit latency (ms)", color=ORANGE)
ax4.tick_params(axis="y", labelcolor=GREEN)
ax4_twin.tick_params(axis="y", labelcolor=ORANGE)
ax4.set_xticks(conc)
ax4.set_title("(d) Fabric TPS vs concurrent voters")

lines = [l1, l2]
labels = [l.get_label() for l in lines]
ax4.legend(lines, labels, loc="center right", fontsize=8)

fig.savefig("fig9_e2e_scalability.png", bbox_inches="tight", dpi=300)
plt.close(fig)
print("[+] Saved fig9_e2e_scalability.png")

# ── Print summary table ────────────────────────────────────────────────────────
print("\n% === Table: LRS Sign Latency vs Ring Size ===")
print("n & Sign (ms) & Verify (ms) & Total Crypto (ms) \\\\")
for r in ring_sw:
    print(f"{r['ring_size']} & {r['p6_lrs_sign']['mean']:.1f}±{r['p6_lrs_sign']['sd']:.1f}"
          f" & {r['p7_lrs_verify']['mean']:.1f}±{r['p7_lrs_verify']['sd']:.1f}"
          f" & {r['total_crypto_mean']:.1f} \\\\")

print("\n% === Table: ElGamal+ZKP vs Candidate Count ===")
print("C & Encrypt+ZKP (ms) & Total Client (ms) \\\\")
for c in cand_sw:
    print(f"{c['candidates']} & {c['elgamal_zkp']['mean']:.1f}±{c['elgamal_zkp']['sd']:.1f}"
          f" & {c['total_client_mean']:.1f}±{c['total_client_sd']:.1f} \\\\")

print("\n% === Table: Fabric TPS vs Concurrency ===")
print("Concurrency & TPS & Submit Latency (ms) \\\\")
for t in tps_sw:
    print(f"{t['concurrency']} & {t['tps']['mean']:.2f}±{t['tps']['sd']:.2f}"
          f" & {t['submit_latency']['mean']:.0f}±{t['submit_latency']['sd']:.0f} \\\\")
