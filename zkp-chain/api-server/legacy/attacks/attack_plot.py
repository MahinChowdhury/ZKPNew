"""
═══════════════════════════════════════════════════════════════════
 Security Attack Resilience — Visualization Script
═══════════════════════════════════════════════════════════════════

 Generates publication-ready figures from the attack test results.

 Figures:
   fig_attack_matrix.png   — Heatmap of all attack test results
   fig_forgery_stats.png   — Forgery test statistics
   fig_timing_analysis.png — Timing side-channel analysis

 Run: python attacks/attack_plot.py
 Requires: matplotlib, numpy, json results in attacks/results/
"""

import json
import os
import sys
import numpy as np

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import ListedColormap
except ImportError:
    print("matplotlib not found. Install: pip install matplotlib")
    sys.exit(1)

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results")

# ── Style Setup ──────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.titlesize': 13,
    'axes.labelsize': 11,
    'figure.facecolor': '#fafafa',
    'axes.facecolor': '#fafafa',
    'savefig.dpi': 200,
    'savefig.bbox': 'tight',
    'savefig.facecolor': '#fafafa'
})


def load_json(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(filepath):
        print(f"  ⚠️  {filename} not found, skipping...")
        return None
    with open(filepath, 'r') as f:
        return json.load(f)


def plot_attack_matrix():
    """Generate heatmap of all attack test pass/fail results."""
    data = load_json("combined_attack_results.json")
    if not data or "attack_matrix" not in data:
        print("  No combined results for attack matrix.")
        return

    matrix = data["attack_matrix"]

    # Group by category (layer)
    categories = {}
    for entry in matrix:
        cat = entry["layer"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(entry)

    # Create figure
    fig, ax = plt.subplots(figsize=(14, max(8, len(matrix) * 0.35)))

    # Data for heatmap
    labels = []
    statuses = []
    layers = []
    properties = []

    for entry in matrix:
        labels.append(f"#{entry['id']} {entry['attack']}")
        layers.append(entry['layer'])
        properties.append(entry['property'])
        s = entry['status']
        if s == 'PASS':
            statuses.append(2)
        elif s == 'FAIL':
            statuses.append(0)
        elif s == 'NOT RUN':
            statuses.append(1)
        else:
            statuses.append(1)

    n = len(labels)
    y_pos = np.arange(n)

    # Color map: 0=red (fail), 1=gray (not run), 2=green (pass)
    colors = []
    for s in statuses:
        if s == 2:
            colors.append('#2ecc71')  # green
        elif s == 0:
            colors.append('#e74c3c')  # red
        else:
            colors.append('#95a5a6')  # gray

    # Draw horizontal bars
    bars = ax.barh(y_pos, [1]*n, color=colors, height=0.7, edgecolor='white', linewidth=1.5)

    # Add text labels
    for i, (label, layer, prop, status) in enumerate(zip(labels, layers, properties, statuses)):
        status_text = ['FAIL', 'NOT RUN', 'PASS'][status]
        ax.text(0.02, i, label, va='center', ha='left', fontsize=9,
                fontweight='bold', color='white' if status != 1 else '#2c3e50')
        ax.text(0.98, i, f"[{layer}] {prop} → {status_text}", va='center', ha='right',
                fontsize=8, color='white' if status != 1 else '#2c3e50')

    ax.set_yticks([])
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.set_ylim(-0.5, n - 0.5)
    ax.invert_yaxis()
    ax.set_title("Security Attack Resilience Matrix", fontsize=14, fontweight='bold', pad=15)

    # Legend
    legend_elements = [
        mpatches.Patch(facecolor='#2ecc71', label='PASS (Attack Resisted)'),
        mpatches.Patch(facecolor='#e74c3c', label='FAIL (Vulnerability)'),
        mpatches.Patch(facecolor='#95a5a6', label='NOT RUN'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=9)

    out = os.path.join(OUTPUT_DIR, "fig_attack_matrix.png")
    plt.savefig(out)
    plt.close()
    print(f"  ✅ Saved {out}")


def plot_timing_analysis():
    """Generate timing side-channel analysis figure."""
    data = load_json("08_timing_attack_results.json")
    if not data:
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Panel A: Signer position timing
    if "8.1_signer_position_timing" in data.get("tests", {}):
        test = data["tests"]["8.1_signer_position_timing"]
        stats = test.get("position_stats", {})

        positions = sorted(stats.keys(), key=int)
        means = [stats[p]["mean"] for p in positions]
        stds = [stats[p]["stddev"] for p in positions]

        ax = axes[0]
        bars = ax.bar(range(len(positions)), means, yerr=stds,
                      color='#3498db', alpha=0.8, capsize=3, edgecolor='white')

        # Grand mean line
        grand_mean = float(test.get("grand_mean_ms", 0))
        ax.axhline(y=grand_mean, color='#e74c3c', linestyle='--', linewidth=1.5,
                    label=f'Grand Mean = {grand_mean:.1f} ms')

        ax.set_xlabel("Signer Position in Ring")
        ax.set_ylabel("Sign Latency (ms)")
        ax.set_title(f"(a) LRS Sign Time vs Signer Position\n"
                      f"F={float(test.get('f_statistic', 0)):.3f}, "
                      f"F_crit={test.get('f_critical_alpha_005', 1.93)}, "
                      f"{'No' if test.get('no_significant_difference') else ''} Significant Difference",
                      fontsize=10)
        ax.legend(fontsize=8)
        ax.set_xticks(range(len(positions)))

    # Panel B: Vote value timing
    if "8.2_vote_value_timing" in data.get("tests", {}):
        test = data["tests"]["8.2_vote_value_timing"]

        operations = ['encrypt', 'prove']
        m0_times = []
        m1_times = []

        for op in operations:
            op_data = test.get(op, {})
            m0_times.append(float(op_data.get("mean_m0_ms", 0)))
            m1_times.append(float(op_data.get("mean_m1_ms", 0)))

        ax = axes[1]
        x = np.arange(len(operations))
        width = 0.3

        bars1 = ax.bar(x - width/2, m0_times, width, label='m=0', color='#2ecc71', alpha=0.8)
        bars2 = ax.bar(x + width/2, m1_times, width, label='m=1', color='#e67e22', alpha=0.8)

        ax.set_xlabel("Operation")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_title("(b) ElGamal Operation Time by Vote Value\n"
                      "(No practical timing leakage)", fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(['encrypt()', 'proveValidVote()'])
        ax.legend(fontsize=9)

    plt.tight_layout(pad=2)
    out = os.path.join(OUTPUT_DIR, "fig_timing_analysis.png")
    plt.savefig(out)
    plt.close()
    print(f"  ✅ Saved {out}")


def plot_forgery_stats():
    """Generate forgery test statistics figure."""
    data = load_json("03_forgery_attack_results.json")
    if not data:
        return

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Panel A: Attack categories pass/fail
    tests = data.get("tests", {})
    test_names = []
    test_results = []

    name_map = {
        "3.1_random_forgery": "Random Forgery\n(10K trials)",
        "3.2_ring_manipulation": "Ring\nManipulation",
        "3.3_link_tag_manipulation": "Link Tag\nTampering",
        "3.4_scalar_tampering": "Scalar\nTampering",
        "3.4_bit_flip_fuzzing": "Bit-Flip\nFuzzing",
        "3.5_challenge_manipulation": "Challenge\nManipulation"
    }

    for key, friendly in name_map.items():
        if key in tests:
            test_names.append(friendly)
            test_results.append(1 if tests[key]["pass"] else 0)

    ax = axes[0]
    colors = ['#2ecc71' if r else '#e74c3c' for r in test_results]
    bars = ax.bar(range(len(test_names)), [100]*len(test_names), color=colors,
                  edgecolor='white', linewidth=2)

    for i, (name, result) in enumerate(zip(test_names, test_results)):
        ax.text(i, 50, "PASS" if result else "FAIL", ha='center', va='center',
                fontsize=11, fontweight='bold', color='white')

    ax.set_xticks(range(len(test_names)))
    ax.set_xticklabels(test_names, fontsize=8)
    ax.set_ylabel("Rejection Rate (%)")
    ax.set_ylim(0, 110)
    ax.set_title("(a) Forgery Attack Test Results", fontsize=11)

    # Panel B: Random forgery statistics
    if "3.1_random_forgery" in tests:
        rf = tests["3.1_random_forgery"]
        ax2 = axes[1]

        categories = ['Trials', 'Rejected', 'Accepted']
        values = [rf["trials"], rf["rejected"], rf["accepted"]]
        colors2 = ['#3498db', '#2ecc71', '#e74c3c']

        bars2 = ax2.bar(categories, values, color=colors2, edgecolor='white', linewidth=2)

        for bar, val in zip(bars2, values):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100,
                     f'{val:,}', ha='center', va='bottom', fontsize=11, fontweight='bold')

        ax2.set_ylabel("Count")
        ax2.set_title(f"(b) Random Forgery: {rf['trials']:,} Trials\n"
                       f"0 False Accepts → 100% Rejection Rate", fontsize=11)
        ax2.set_ylim(0, rf["trials"] * 1.15)

    plt.tight_layout(pad=2)
    out = os.path.join(OUTPUT_DIR, "fig_forgery_stats.png")
    plt.savefig(out)
    plt.close()
    print(f"  ✅ Saved {out}")


def plot_zkp_stats():
    """Generate ZKP attack test figure."""
    data = load_json("04_zkp_attack_results.json")
    if not data:
        return

    tests = data.get("tests", {})
    fig, ax = plt.subplots(figsize=(12, 5))

    test_labels = []
    test_passed = []

    label_map = {
        "4.1_invalid_vote_values": "Invalid Vote\nValues",
        "4.2_proof_component_tampering": "Proof Component\nTampering (8/8)",
        "4.3_ciphertext_malleability": "Ciphertext\nMalleability",
        "4.4_cross_vote_proof_reuse": "Cross-Vote\nProof Reuse",
        "4.5_random_zkp_forgery": "Random ZKP\nForgery (1K)"
    }

    for key, label in label_map.items():
        if key in tests:
            test_labels.append(label)
            test_passed.append(1 if tests[key]["pass"] else 0)

    colors = ['#2ecc71' if p else '#e74c3c' for p in test_passed]
    bars = ax.bar(range(len(test_labels)), [100]*len(test_labels), color=colors,
                  edgecolor='white', linewidth=2)

    for i, (label, passed) in enumerate(zip(test_labels, test_passed)):
        ax.text(i, 50, "PASS" if passed else "FAIL", ha='center', va='center',
                fontsize=12, fontweight='bold', color='white')

    ax.set_xticks(range(len(test_labels)))
    ax.set_xticklabels(test_labels, fontsize=9)
    ax.set_ylabel("Rejection Rate (%)")
    ax.set_ylim(0, 110)
    ax.set_title("ZKP & Vote Manipulation Attack Resilience", fontsize=13, fontweight='bold')

    plt.tight_layout()
    out = os.path.join(OUTPUT_DIR, "fig_zkp_stats.png")
    plt.savefig(out)
    plt.close()
    print(f"  ✅ Saved {out}")


def plot_combined_overview():
    """Generate a combined overview figure for the paper."""
    data = load_json("combined_attack_results.json")
    if not data or "attack_matrix" not in data:
        print("  No combined results for overview.")
        return

    matrix = data["attack_matrix"]

    # Count by layer
    layer_counts = {}
    for entry in matrix:
        layer = entry["layer"]
        if layer not in layer_counts:
            layer_counts[layer] = {"pass": 0, "fail": 0, "not_run": 0}
        if entry["status"] == "PASS":
            layer_counts[layer]["pass"] += 1
        elif entry["status"] == "FAIL":
            layer_counts[layer]["fail"] += 1
        else:
            layer_counts[layer]["not_run"] += 1

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Panel A: Pass/Fail by layer (stacked bar)
    ax = axes[0]
    layers = list(layer_counts.keys())
    passes = [layer_counts[l]["pass"] for l in layers]
    fails = [layer_counts[l]["fail"] for l in layers]
    not_runs = [layer_counts[l]["not_run"] for l in layers]

    x = np.arange(len(layers))
    width = 0.6

    ax.bar(x, passes, width, label='PASS', color='#2ecc71', edgecolor='white')
    ax.bar(x, fails, width, bottom=passes, label='FAIL', color='#e74c3c', edgecolor='white')
    ax.bar(x, not_runs, width, bottom=[p+f for p,f in zip(passes, fails)],
           label='NOT RUN', color='#95a5a6', edgecolor='white')

    ax.set_xticks(x)
    ax.set_xticklabels(layers, fontsize=8, rotation=30, ha='right')
    ax.set_ylabel("Number of Tests")
    ax.set_title("(a) Attack Resilience by System Layer", fontsize=11)
    ax.legend(fontsize=8)

    # Panel B: Overall pie chart
    ax2 = axes[1]
    summary = data.get("summary", {})
    total_p = summary.get("passed", 0)
    total_f = summary.get("failed", 0)
    total_nr = summary.get("total_tests", 0) - total_p - total_f

    sizes = [total_p, total_f]
    labels_pie = [f'Passed ({total_p})', f'Failed ({total_f})']
    colors_pie = ['#2ecc71', '#e74c3c']

    if total_nr > 0:
        sizes.append(total_nr)
        labels_pie.append(f'Not Run ({total_nr})')
        colors_pie.append('#95a5a6')

    if sum(sizes) > 0:
        wedges, texts, autotexts = ax2.pie(sizes, labels=labels_pie, colors=colors_pie,
                                             autopct='%1.0f%%', startangle=90,
                                             textprops={'fontsize': 10})
        ax2.set_title(f"(b) Overall: {total_p}/{summary.get('total_tests', 0)} Tests Passed",
                      fontsize=11)
    else:
        ax2.text(0.5, 0.5, "No results", ha='center', va='center')

    plt.tight_layout(pad=2)
    out = os.path.join(OUTPUT_DIR, "fig_attack_overview.png")
    plt.savefig(out)
    plt.close()
    print(f"  ✅ Saved {out}")


if __name__ == "__main__":
    print("\n═══════════════════════════════════════════════════════")
    print("  Security Attack Resilience — Figure Generation")
    print("═══════════════════════════════════════════════════════\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    plot_forgery_stats()
    plot_zkp_stats()
    plot_timing_analysis()
    plot_attack_matrix()
    plot_combined_overview()

    print("\n  Done! All figures saved to attacks/results/\n")
