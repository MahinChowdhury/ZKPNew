"""Build one face-circuit variant per soundness pitfall (one fix removed each) and run Circomspect on all.

Usage: python3 make_variants.py <circuits_dir> <out_dir>
Writes <out_dir>/<variant>/ (sources + node_modules link) and <out_dir>/summary.json.
"""
import json
import os
import re
import shutil
import subprocess
import sys

CIRCUITS, OUT = sys.argv[1], sys.argv[2]
CIRCOMSPECT = os.path.expanduser("~/.cargo/bin/circomspect")
FILES = ["face_auth.circom", "common.circom", "face_common.circom"]


def must_replace(text, old, new):
    assert old in text, f"pattern not found: {old[:60]!r}"
    return text.replace(old, new)


# P2: the threshold becomes two public inputs the verifier does not pin.
P2_COSINE = """
template SquaredCosineSimilarityPub(n, coordBits) {
    var logN = 0;
    while ((1 << logN) < n) { logN++; }
    var dotBits = 2 * coordBits + logN;
    var cmpBits = 2 * dotBits + 14;
    signal input a[n];
    signal input b[n];
    signal input thNum;
    signal input thDen;
    signal output pass;
    component rangeA[n];
    component rangeB[n];
    for (var i = 0; i < n; i++) {
        rangeA[i] = SignedRangeCheck(coordBits);
        rangeA[i].in <== a[i];
        rangeB[i] = SignedRangeCheck(coordBits);
        rangeB[i].in <== b[i];
    }
    signal dot_terms[n];
    signal dot_accum[n + 1];
    dot_accum[0] <== 0;
    for (var i = 0; i < n; i++) {
        dot_terms[i] <== a[i] * b[i];
        dot_accum[i + 1] <== dot_accum[i] + dot_terms[i];
    }
    signal dot_product <== dot_accum[n];
    component dotNonNeg = Num2Bits(dotBits);
    dotNonNeg.in <== dot_product;
    signal na_t[n]; signal na[n + 1]; na[0] <== 0;
    signal nb_t[n]; signal nb[n + 1]; nb[0] <== 0;
    for (var i = 0; i < n; i++) {
        na_t[i] <== a[i] * a[i]; na[i + 1] <== na[i] + na_t[i];
        nb_t[i] <== b[i] * b[i]; nb[i + 1] <== nb[i] + nb_t[i];
    }
    signal dot_sq <== dot_product * dot_product;
    signal lhs <== dot_sq * thDen;
    signal norms <== na[n] * nb[n];
    signal rhs <== thNum * norms;
    component gte = GreaterEqThan(cmpBits);
    gte.in[0] <== lhs;
    gte.in[1] <== rhs;
    pass <== gte.out;
}
"""


def p1(src):  # free live witness: drop the sensor attestation block
    f = src["face_auth.circom"]
    start = f.index("    component liveHash = PackedCoordHash")
    end = f.index("    // =====================\n    // 6.")
    f = f[:start] + f[end:]
    # A design without attestation has no attestation inputs either.
    s = f.index("    // Sensor attestation (see common.circom)")
    e = f.index("    // --- Output ---")
    f = f[:s] + f[e:]
    f = must_replace(f, "    signal input sensorRoot;             // Root of the authorised-sensor registry\n", "")
    f = must_replace(f, ", voteBinding, sensorRoot]}", ", voteBinding]}")
    src["face_auth.circom"] = f


def p2(src):
    f = src["face_auth.circom"]
    f = must_replace(f, "// FaceAuth — Main circuit", P2_COSINE + "\n// FaceAuth — Main circuit")
    f = must_replace(f, "    signal input sensorRoot;", "    signal input sensorRoot;\n    signal input thresholdNum;\n    signal input thresholdDen;")
    f = must_replace(f, "component cosine = SquaredCosineSimilarity(embeddingSize, thNum, thDen, COORD_BITS);",
                     "component cosine = SquaredCosineSimilarityPub(embeddingSize, COORD_BITS);\n"
                     "    cosine.thNum <== thresholdNum;\n    cosine.thDen <== thresholdDen;")
    f = must_replace(f, "sensorRoot]}", "sensorRoot, thresholdNum, thresholdDen]}")
    # The threshold is no longer a template parameter at all.
    f = must_replace(f, "template FaceAuth(embeddingSize, treeLevels, thNum, thDen, sensorLevels)",
                     "template FaceAuth(embeddingSize, treeLevels, sensorLevels)")
    f = must_replace(f, "FaceAuth(128, 20, 1225, 10000, 10)", "FaceAuth(128, 20, 10)")
    src["face_auth.circom"] = f


def p3(src):  # unconstrained Merkle direction bits
    src["common.circom"] = must_replace(src["common.circom"], "        pathIndices[i] * (pathIndices[i] - 1) === 0;\n", "")


def p4(src):  # no coordinate range checks, no sign check (also breaks packing injectivity)
    f = src["face_auth.circom"]
    f = re.sub(r"    component rangeA\[n\];.*?\n    }\n", "", f, count=1, flags=re.S)
    f = must_replace(f, "    component dotNonNeg = Num2Bits(dotBits);\n    dotNonNeg.in <== dot_product;\n", "")
    src["face_auth.circom"] = f
    # PackedCoordHash range-checks nothing itself; leave it as is.


def p5(src):  # public inputs that appear in no constraint: vb and the nullifier check
    f = src["face_auth.circom"]
    f = must_replace(f, "    signal voteBindingSq <== voteBinding * voteBinding;\n", "")
    f = must_replace(f, "    nullifierHasher.out === nullifier;\n", "")
    src["face_auth.circom"] = f


VARIANTS = {"fixed": None, "P1_free_live_witness": p1, "P2_public_threshold": p2,
            "P3_path_bits": p3, "P4_no_range_checks": p4, "P5_unbound_public_inputs": p5}

ISSUE = re.compile(r"^(warning|error|note): (.+)$")
LOC = re.compile(r"┌─ .*/([^/]+\.circom):(\d+)")


def run(variant_dir):
    out = subprocess.run([CIRCOMSPECT, "-L", "node_modules", "face_auth.circom"], cwd=variant_dir,
                         capture_output=True, text=True).stdout
    issues, current = [], None
    for line in out.splitlines():
        m = ISSUE.match(line.strip())
        if m:
            current = {"level": m.group(1), "message": m.group(2)}
            issues.append(current)
        elif current and "loc" not in current and (n := LOC.search(line)):
            current["loc"] = f"{n.group(1)}:{n.group(2)}"
    open(os.path.join(variant_dir, "circomspect.txt"), "w").write(out)
    return issues


summary = {}
os.makedirs(OUT, exist_ok=True)
for name, mutate in VARIANTS.items():
    d = os.path.join(OUT, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    src = {f: open(os.path.join(CIRCUITS, f)).read() for f in FILES}
    if mutate:
        mutate(src)
    for f, text in src.items():
        open(os.path.join(d, f), "w").write(text)
    os.symlink(os.path.join(CIRCUITS, "node_modules"), os.path.join(d, "node_modules"))
    summary[name] = run(d)

base = {(i["message"]) for i in summary["fixed"]}
for name, issues in summary.items():
    new = [i for i in issues if i["message"] not in base]
    print(f"{name}: {len(issues)} issues, {len(new)} not in fixed")
    for i in new:
        print(f"    + [{i['level']}] {i['message']}  ({i.get('loc', '?')})")
json.dump(summary, open(os.path.join(OUT, "summary.json"), "w"), indent=1)
