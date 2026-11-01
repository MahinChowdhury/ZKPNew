"""
make_numbers.py — emit numbers.tex: every measured number the paper quotes, as a macro.

Each macro is read from a generated result file, never typed by hand (Phase 5 of
docs/revision/REVISION_PLAN.md). build.sh runs this before compiling, so a re-run
experiment changes the paper on the next build. A missing file or key fails the build.

Macros hold the bare number (no % or unit), so they work in text and math:
  \\nLfwEer -> 0.22    \\nFaceConstraints -> 32{,}950    \\nProveMs -> 1{,}669

Usage: python3 make_numbers.py   (from anywhere; writes numbers.tex next to this file)
"""

import json
import math
import os
import re
from decimal import ROUND_HALF_UP, Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BENCH = os.path.join(REPO, "api-server", "benchmark")
RESULTS = os.path.join(REPO, "api-server", "results")


def load(*parts):
    with open(os.path.join(REPO, *parts)) as f:
        return json.load(f)


def rnd(x, nd):
    """Half-up rounding of the decimal value as stored (no binary-float surprises)."""
    q = Decimal(1).scaleb(-nd) if nd > 0 else Decimal(1)
    return Decimal(str(x)).quantize(q, rounding=ROUND_HALF_UP)


def num(x, nd=0):
    """Fixed decimals, LaTeX thousands separator: 32950 -> 32{,}950."""
    s = f"{rnd(x, nd):,.{nd}f}" if nd > 0 else f"{int(rnd(x, 0)):,}"
    return s.replace(",", "{,}")


def ci(x):
    """A 95% CI half-width in ms: whole ms, or one decimal when it would round to 0."""
    return num(x) if rnd(x, 0) > 0 else num(x, 1)


def pct(x, nd=2):
    """A rate stored as a fraction, printed as a percentage without the % sign."""
    return num(Decimal(str(x)) * 100, nd)


acc = load("api-server", "benchmark", "biometric_accuracy_pca_insightface128.json")
facenet = load("api-server", "benchmark", "biometric_accuracy_pca.json")
op = load("api-server", "benchmark", "operating_point_targeted.json")["selected"]
op96 = load("api-server", "benchmark", "operating_point_insightface.json")["per_dim"]["96"]
look = load("api-server", "benchmark", "targeted_impostor_d128_t35.json")
look96 = load("api-server", "benchmark", "targeted_impostor_d96_t33.json")
cross = load("api-server", "benchmark", "cross_lfw_eval.json")["sets"]
cons = load("api-server", "results", "subcircuit_constraints.json")
lat = load("api-server", "results", "latency_results.json")["phases"]
zkey_bytes = os.path.getsize(os.path.join(REPO, "api-server", "circuits", "face_auth.zkey"))
iris_zkey_bytes = os.path.getsize(os.path.join(REPO, "api-server", "circuits", "iris_auth.zkey"))

M = {}

# Deployed operating point (validation-selected) and its test accuracy
M["nDim"] = num(op["dim"])
M["nTau"] = num(op["tau"], 2)
M["nTauNum"] = num(op["tau_num"])
M["nLfwEer"] = pct(acc["lfw"]["eer"])
M["nLfwEerLo"] = pct(acc["lfw"]["ci95"][0])
M["nLfwEerHi"] = pct(acc["lfw"]["ci95"][1])
M["nFrr"] = pct(op["test_frr"])
M["nFar"] = pct(op["test_far"], 3)
M["nFalseAccepts"] = num(op["test_false_accepts"])
M["nImpostorPairs"] = num(op["test_impostor_pairs"])
# K-screening bound (Proposition prop:lookalike): 1 - (1 - FAR)^K at the deployed point
for k, word in ((10, "Ten"), (100, "Hundred"), (1000, "Thousand")):
    M[f"nLookBound{word}"] = pct(1 - (1 - op["test_far"]) ** k, 2 if k < 1000 else 1)
M["nFacenetEer"] = pct(facenet["lfw"]["eer"])
M["nFacenetEerLo"] = pct(facenet["lfw"]["ci95"][0])
M["nFacenetEerHi"] = pct(facenet["lfw"]["ci95"][1])

# Cross-dataset, fairness, inversion
M["nCelebaEer"] = pct(acc["celeba"]["eer"])
M["nCelebaEerLo"] = pct(acc["celeba"]["ci95"][0])
M["nCelebaEerHi"] = pct(acc["celeba"]["ci95"][1])
M["nCelebaEmbedded"] = num(acc["celeba"]["embedded"][0])
M["nCelebaImages"] = num(acc["celeba"]["embedded"][1])
fm, ff = acc["fairness"]["male"], acc["fairness"]["female"]
M["nMaleEer"], M["nMaleEerLo"], M["nMaleEerHi"] = pct(fm["eer"]), pct(fm["ci95"][0]), pct(fm["ci95"][1])
M["nFemaleEer"], M["nFemaleEerLo"], M["nFemaleEerHi"] = pct(ff["eer"]), pct(ff["ci95"][0]), pct(ff["ci95"][1])
M["nMaleIds"], M["nFemaleIds"] = num(fm["n_identities"]), num(ff["n_identities"])
M["nGenderGap"] = pct(ff["eer"] - fm["eer"], 1)
M["nGenderRatio"] = num(ff["eer"] / fm["eer"], 1)
sweep = load("api-server", "benchmark", "face_sweep_insightface.json")
deepface = load("api-server", "benchmark", "biometric_accuracy_ArcFace.json")["face"]["bootstrap"]["eer"]["raw"]
M["nCelebaRawEer"] = pct(sweep["celeba"]["raw"])
M["nFacenetCelebaEer"] = pct(facenet["celeba"]["eer"])
M["nFacenetMaleEer"] = pct(facenet["fairness"]["male"]["eer"])
M["nFacenetFemaleEer"] = pct(facenet["fairness"]["female"]["eer"])
M["nDeepfaceEer"] = pct(deepface["eer"])
M["nDeepfaceRatio"] = num(deepface["eer"] / sweep["eer"]["raw"]["eer"])
M["nRawEer"] = pct(sweep["eer"]["raw"]["eer"])
M["nInvCos"] = num(acc["inversion"]["mean_cosine_to_true"], 2)
M["nInvEer"] = pct(acc["inversion"]["impersonation_eer"])
M["nInvRawEer"] = pct(acc["inversion"]["raw_eer"])

# CALFW / CPLFW
for name, key in (("calfw", "Calfw"), ("cplfw", "Cplfw")):
    a, u = cross[name]["all"], cross[name]["unseen"]
    M[f"n{key}Eer"] = pct(a["eer_pca"]["eer"])
    M[f"n{key}EerLo"] = pct(a["eer_pca"]["ci95"][0])
    M[f"n{key}EerHi"] = pct(a["eer_pca"]["ci95"][1])
    M[f"n{key}RawEer"] = pct(a["eer_raw"]["eer"])
    M[f"n{key}Frr"] = pct(a["circuit_frr"], 1)
    M[f"n{key}Far"] = pct(a["circuit_far"])
    M[f"n{key}UnseenFrr"] = pct(u["circuit_frr"], 1)
    M[f"n{key}Images"] = num(cross[name]["images"])
    M[f"n{key}Embedded"] = num(cross[name]["embedded"])

# Lookalike attack: K = 1, 10, 100, 1000 recruits (Table tab:lookalike)
KS = (("1", "One"), ("10", "Ten"), ("100", "Hundred"), ("1000", "Thousand"))


def lookalike_row(prefix, by_pool):
    for k, word in KS:
        r = by_pool[k]["success_rate"]
        # three decimals below 0.01%, one at 1% and above, two in between
        nd = 3 if r < 1e-4 else (1 if r >= 1e-2 else 2)
        M[f"{prefix}{word}"] = pct(r, nd)


lookalike_row("nLookLfw", look["lfw"]["by_pool_size"])
lookalike_row("nLookCeleba", look["celeba"]["by_pool_size"])
lookalike_row("nLookGender", look["celeba"]["same_gender_by_pool_size"])
lookalike_row("nZeLookLfw", look96["lfw"]["by_pool_size"])
lookalike_row("nZeLookCeleba", look96["celeba"]["by_pool_size"])
lookalike_row("nZeLookGender", look96["celeba"]["same_gender_by_pool_size"])
M["nZeFrr"] = pct(op96["test_frr"])

# Circuit size (circom --O2, measure_subcircuits.sh)
d = op["dim"]
M["nFaceConstraints"] = num(cons["face_auth (full)"])
M["nIrisConstraints"] = num(cons["iris_auth (full)"])
M["nEnrollConstraints"] = num(cons["enroll_auth (full)"])
M["nEnrollDomainExp"] = num(math.ceil(math.log2(cons["enroll_auth (full)"] + 3 + 1)))
M["nHashConstraints"] = num(cons[f"PackedCoordHash({d})"])
M["nChunkedHash"] = num(cons[f"PoseidonHashChunked({d},8)"])
M["nCosConstraints"] = num(cons[f"SquaredCosineSimilarity({d})"])
M["nEuclidConstraints"] = num(cons[f"SquaredEuclideanDistance({d})"])
M["nMerkleConstraints"] = num(cons["MerkleTreeChecker(20)"])
M["nAttestConstraints"] = num(cons["SensorAttestation(10)"])
M["nKeyMB"] = num(zkey_bytes / 1e6, 1)
M["nIrisKeyMB"] = num(iris_zkey_bytes / 1e6, 1)
M["nAttestShare"] = num(100 * cons["SensorAttestation(10)"] / cons["face_auth (full)"])
M["nPoseidonTwo"] = num(cons["Poseidon(2)"])
M["nPackedHash"] = num(cons["PackedBitsHash(256)"])
M["nHamming"] = num(cons["HammingDistance(256)"])


def read(*parts):
    with open(os.path.join(REPO, *parts)) as f:
        return f.read()


# Fixed-point scale and range bounds, read from the deployed client and circuit
sigma = int(re.search(r"FACE_SCALE = (\d+);", read("frontend", "src", "crypto", "voterClient.js")).group(1))
coord_bits = int(re.search(r"var COORD_BITS = (\d+);",
                           read("api-server", "circuits", "face_auth.circom")).group(1))
assert sigma < 2 ** coord_bits, "sigma must fit the circuit's coordinate range check"
exp = len(str(sigma)) - 1
M["nSigma"] = f"{sigma // 10 ** exp} \\times 10^{{{exp}}}" if sigma % 10 ** exp == 0 else num(sigma)
M["nCoordBits"] = num(coord_bits)
M["nTwoCoordBits"] = num(2 * coord_bits)
M["nRangePerCoord"] = num(coord_bits + 1)                 # Num2Bits(coordBits + 1) per coordinate
M["nRangeConstraints"] = num(2 * d * (coord_bits + 1))    # both vectors
dot_bits = 2 * coord_bits + math.ceil(math.log2(d))       # same derivation as the circuit
M["nDotBits"] = num(dot_bits)
M["nCmpBits"] = num(2 * dot_bits + 14)
n_public = load("api-server", "circuits", "verification_key.json")["nPublic"]
M["nDomainExp"] = num(math.ceil(math.log2(cons["face_auth (full)"] + n_public + 1)))


def substituted(dim, metric):
    """Full face circuit at another dimension/metric: the template is hashed twice (supp. Table S3)."""
    return (cons["face_auth (full)"]
            + 2 * (cons[f"PackedCoordHash({dim})"] - cons[f"PackedCoordHash({d})"])
            + cons[f"{metric}({dim})"] - cons[f"SquaredCosineSimilarity({d})"])


for dim, word in ((16, "Sixteen"), (64, "SixtyFour"), (96, "NinetySix"), (160, "OneSixty"), (256, "TwoFiftySix"),
                  (512, "FiveTwelve")):
    M[f"nHash{word}"] = num(cons[f"PackedCoordHash({dim})"])
    M[f"nCos{word}"] = num(cons[f"SquaredCosineSimilarity({dim})"])
    M[f"nFullCos{word}"] = num(substituted(dim, "SquaredCosineSimilarity"))
M["nOneSixtyExtra"] = num(100 * (substituted(160, "SquaredCosineSimilarity") / cons["face_auth (full)"] - 1))
M["nPerDim"] = num((substituted(256, "SquaredCosineSimilarity") - substituted(16, "SquaredCosineSimilarity")) / 240)
# Packed vs per-coordinate (chunked) template hashing at the deployed d
chunked_full = cons["face_auth (full)"] + 2 * (cons[f"PoseidonHashChunked({d},8)"] - cons[f"PackedCoordHash({d})"])
M["nChunkedFull"] = num(chunked_full)
M["nPackSave"] = num(100 * (1 - cons["face_auth (full)"] / chunked_full))
M["nChunkedPerDim"] = num((2 * (cons["PoseidonHashChunked(256,8)"] - cons["PoseidonHashChunked(16,8)"])
                           + cons["SquaredCosineSimilarity(256)"] - cons["SquaredCosineSimilarity(16)"]) / 240)
M["nFiveTwelveDomainExp"] = num(math.ceil(math.log2(substituted(512, "SquaredCosineSimilarity") + n_public + 1)))
M["nEuclidSixtyFour"] = num(cons["SquaredEuclideanDistance(64)"])
M["nFullEuclidSixtyFour"] = num(substituted(64, "SquaredEuclideanDistance"))
M["nFullEuclid"] = num(substituted(d, "SquaredEuclideanDistance"))
M["nEuclidSaveSixtyFour"] = num(cons["SquaredCosineSimilarity(64)"] - cons["SquaredEuclideanDistance(64)"])
M["nEuclidSave"] = num(cons[f"SquaredCosineSimilarity({d})"] - cons[f"SquaredEuclideanDistance({d})"])
M["nEuclidSaveShare"] = num(100 * (cons[f"SquaredCosineSimilarity({d})"] - cons[f"SquaredEuclideanDistance({d})"])
                            / cons["face_auth (full)"], 1)

# Real-browser run (bench_browser.py: Playwright + Edge, the React client end to end)
br = load("api-server", "results", "browser_results.json")
assert br["impostorRejected"] and br["doubleVoteRejected"] and br["tallyMatches"], "browser run not clean"
M["nBrowserVoters"] = num(br["votesAccepted"])
M["nBrowserName"] = "Edge " + re.search(r"Edg/(\d+)", br["browser"]).group(1)
M["nBrowserProveMs"] = num(br["phases"]["prove"]["mean"])
M["nBrowserProveCi"] = num(br["phases"]["prove"]["ci95"])
M["nBrowserClientMs"] = num(br["clientTotal"]["mean"])
M["nBrowserClientCi"] = num(br["clientTotal"]["ci95"])
M["nBrowserClientS"] = num(br["clientTotal"]["mean"] / 1000, 2)
M["nBrowserColdMs"] = num(br["coldFirstVote"]["total"])
M["nBrowserSubmitS"] = num(br["submitToConfirmed"]["mean"] / 1000, 1)
M["nBrowserEnrollMs"] = num(br["enrollProve"]["mean"])
M["nBrowserEnrollCi"] = num(br["enrollProve"]["ci95"])

# Attack suite (run_soundness_attacks.js): attacks rejected by the deployed circuits + chaincode
attacks = load("api-server", "attacks", "soundness", "results", "soundness_results.json")["results"]
assert not [r for r in attacks if r["outcome"] in ("VULNERABLE", "OPEN", "HARNESS-FAIL")], "attack suite not clean"
M["nAttacks"] = num(sum(r["outcome"] == "PROTECTED" for r in attacks))

# Latency (bench_client.mjs: mean and 95% CI, ms)
face, iris = lat["face"], lat["iris"]
for key, phase in (("Merkle", "merklePaths"), ("Encrypt", "encryptBallot"), ("Witness", "witness"), ("Prove", "prove"),
                   ("Client", "clientTotal"), ("Sign", "deviceSign"), ("Verify", "groth16Verify"),
                   ("CastVote", "castVote")):
    M[f"n{key}Ms"] = num(face[phase]["mean"])
    M[f"n{key}Ci"] = ci(face[phase]["ci95"])
M["nProveShare"] = num(100 * face["prove"]["mean"] / face["clientTotal"]["mean"])
M["nProveS"] = num(face["prove"]["mean"] / 1000, 2)
M["nClientS"] = num(face["clientTotal"]["mean"] / 1000, 1)
M["nIrisProveS"] = num(iris["prove"]["mean"] / 1000, 2)
for key, phase in (("Witness", "witness"), ("Prove", "prove"), ("Client", "clientTotal"),
                   ("Sign", "deviceSign"), ("Verify", "groth16Verify"), ("CastVote", "castVote")):
    M[f"nIris{key}Ms"] = num(iris[phase]["mean"])
    M[f"nIris{key}Ci"] = ci(iris[phase]["ci95"])
scaling = load("api-server", "results", "latency_results.json")["scaling"]   # Table tab:scaling, N rows
for n, word in (("10", "Ten"), ("1000", "Thousand"), ("5000", "FiveThousand"), ("20000", "TwentyThousand")):
    M[f"nScale{word}PathsMs"] = num(scaling[n]["clientMerkle"]["mean"])
    M[f"nScale{word}ProveMs"] = num(scaling[n]["prove"]["mean"])
    M[f"nScale{word}CastMs"] = num(scaling[n]["castVote"]["mean"])
cast_means = [s["castVote"]["mean"] for s in scaling.values()]
M["nScaleCastMin"], M["nScaleCastMax"] = num(min(cast_means)), num(max(cast_means))
M["nScalePathsTopS"] = num(scaling["20000"]["clientMerkle"]["mean"] / 1000, 1)
M["nScalePathsMillionS"] = num(scaling["20000"]["clientMerkle"]["mean"] / 1000 * 50)   # linear to 10^6
tallies = load("api-server", "results", "latency_results.json")["tally"]
tally = tallies["1000"]
M["nTallyVerifyMs"] = num(tally["verifyAndAggregateMs"] / 1000)   # trustee re-verification, per ballot
M["nTallyPublishS"] = num(tally["publishTallyMs"] / 1000, 2)
# Linear extrapolation to 10^6 ballots of the single-transaction on-chain tally check (minutes)
M["nTallyMillionMin"] = num(tally["publishTallyMs"] * 1000 / 60000)
for m, word in (("100", "Hundred"), ("1000", "Thousand")):   # Table tab:scaling, tally rows
    M[f"nTally{word}VerifyS"] = num(tallies[m]["verifyAndAggregateMs"] / 1000, 1)
    M[f"nTally{word}DecryptMs"] = num(tallies[m]["thresholdDecryptMs"])
    M[f"nTally{word}PublishMs"] = num(tallies[m]["publishTallyMs"])
# Live Fabric network (bench_fabric.mjs, 128-D chaincode)
fab = load("api-server", "results", "fabric_results.json")
conc = fab["castVoteConcurrent"]
M["nFabVoters"] = num(fab["voters"])
M["nFabInFlight"] = num(fab["concurrency"])
M["nFabSeqS"] = num(fab["castVoteSequential"]["mean"] / 1000, 2)
M["nFabConcS"] = num(conc["latency"]["mean"] / 1000, 2)
M["nFabTps"] = num(conc["throughputTps"])
M["nFabMillionH"] = num(1e6 / conc["throughputTps"] / 3600)   # 10^6 votes at that rate, hours
M["nFabRegisterS"] = num(fab["register"]["mean"] / 1000, 2)
M["nFabPublishS"] = num(fab["tally"]["publishTallyMs"] / 1000, 2)
M["nFabKeygenS"] = num(fab["keygen"]["totalMs"] / 1000, 1)
assert conc["failed"] == 0 and fab["tally"]["totalsMatchCommittedVotes"], "live run lost votes"
M["nIrisProveShare"] = num(100 * iris["prove"]["mean"] / iris["clientTotal"]["mean"])
# Deployed 128-D vs raw 512-D on the voter's prover (benchmark/bench_dim.sh; witness + proof, WASM)
dims = {r["dim"]: r for r in load("api-server", "results", "dim_cost.json")["results"]}
d128, d512 = dims[128], dims[512]
assert d128["constraints"] == cons["face_auth (full)"] and \
    num(d512["constraints"]) == M["nFullCosFiveTwelve"], "dim_cost.json was measured on other circuits"
M["nDimProveMs"] = num(d128["prove_ms_mean"])
M["nRawProveMs"] = num(d512["prove_ms_mean"])
M["nRawProveIncrease"] = num(100 * (d512["prove_ms_mean"] / d128["prove_ms_mean"] - 1))
M["nRawKeyMB"] = num(d512["zkey_bytes"] / 1e6, 1)
M["nRawExtraMemMB"] = num((d512["peak_rss_bytes"] - d128["peak_rss_bytes"]) / 1e6)   # peak RSS of the Node prover
# Phone, same prover and production keys (benchmark/phone/, saved from the phone's browser)
phone = load("api-server", "results", "phone_results.json")
assert phone["zkey_bytes"] == zkey_bytes, "phone run used a different proving key"
M["nPhoneDevice"] = re.sub(r"(?i)^iphone", "iPhone", phone["device"])
M["nPhoneProveMs"] = num(phone["prove_ms_mean"])
M["nPhoneProveCi"] = num(phone["prove_ms_ci95"])
M["nPhoneRatio"] = num(phone["prove_ms_mean"] / d128["prove_ms_mean"], 1)

with open(os.path.join(HERE, "numbers.tex"), "w") as f:
    f.write("% Generated by make_numbers.py from api-server/{benchmark,results}/*.json. Do not edit.\n")
    for k, v in M.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(f"numbers.tex: {len(M)} macros")
