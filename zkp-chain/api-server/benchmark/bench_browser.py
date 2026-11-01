"""
bench_browser.py — end-to-end run of the real web client in a real browser

Drives the React client (vite dev server) with Playwright through the whole
election, exactly as a voter would click it:
  ballot creation (+ 2-of-3 trustee key) -> N face enrollments (credential
  file downloaded) -> N votes, each with a *different* photo of the enrolled
  person -> impostor attempt -> double-vote attempt -> tally.
The vote page logs prepareVote's per-phase timings ("bbzkv-timings", local
only); this script collects them, so proving time is measured in the
browser's own WASM engine.

Prerequisites: Fabric network + chaincode, api-server (:3000), model/app.py
(:8000), sensor/attestor.js (:8001, key registered), vite (:5173).
Runs on the Windows side with Microsoft Edge:
  python -m pip install playwright
  python api-server/benchmark/bench_browser.py [voters=10]
Output: api-server/results/browser_results.json, screenshots in
        api-server/results/browser_screens/
"""
import json
import os
import platform
import random
import re
import statistics
import sys
import time
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
LFW = REPO / "Datasets" / "lfw_kaggle" / "lfw-deepfunneled" / "lfw-deepfunneled"
OUT = REPO / "api-server" / "results"
SHOTS = OUT / "browser_screens"
URL = "http://localhost:5173/"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
PASSWORD = "correct horse battery staple"
OPTIONS = ["Alice", "Bob", "Carol"]
TIMEOUT = 180_000


def identities(n):
    """First n LFW people (sorted) with at least two images; one impostor after them."""
    people = []
    for d in sorted(LFW.iterdir()):
        imgs = sorted(d.glob("*.jpg"))
        if len(imgs) >= 2:
            people.append((d.name, imgs[0], imgs[1]))
        if len(people) == n + 1:
            break
    return people[:n], people[n]


TABS = {"register": "Register", "ballot": "Create Election", "vote": "Cast Vote", "tally": "Tally Results"}


def tab(page, name):
    """Open a view freshly: views are conditionally rendered, so leaving and
    re-entering remounts the form and clears the previous status banner."""
    other = "tally" if name != "tally" else "register"
    page.get_by_role("button", name=TABS[other], exact=True).click()
    page.get_by_role("button", name=TABS[name], exact=True).click()


def wait_outcome(page):
    """Wait for the form's success or error banner and return (ok, text)."""
    banner = page.locator(".alert-success, .alert-error").first
    banner.wait_for(timeout=TIMEOUT)
    text = banner.inner_text()
    cls = banner.get_attribute("class") or ""
    return ("success" in cls), text


def shot(page, path, until=".alert"):
    """Card from its top edge to the bottom of `until` (status banner or results)."""
    card = page.locator(".card", has=page.locator(until)).first
    box, end = card.bounding_box(), page.locator(until).first.bounding_box()
    card.screenshot(path=path)
    scale = page.evaluate("devicePixelRatio")
    im = Image.open(path)
    im.crop((0, 0, im.width, min(im.height, round((end["y"] + end["height"] + 14 - box["y"]) * scale)))).save(path)


def ci95(xs):
    return 1.96 * statistics.stdev(xs) / len(xs) ** 0.5 if len(xs) > 1 else 0.0


def main():
    SHOTS.mkdir(parents=True, exist_ok=True)
    voters, impostor = identities(N)
    timings, walls, log, enroll_ms = [], [], [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        # Phone-width viewport at 2x: narrow cards stay legible when tiled in a paper column
        ctx = browser.new_context(accept_downloads=True, viewport={"width": 430, "height": 932}, device_scale_factor=2)
        page = ctx.new_page()
        page.on("console", lambda m: m.text.startswith("bbzkv-timings ") and
                timings.append(json.loads(m.text.split(" ", 1)[1])))
        page.on("console", lambda m: m.text.startswith("bbzkv-enroll-ms ") and
                enroll_ms.append(float(m.text.split(" ", 1)[1])))
        page.goto(URL)
        # LFW faces are real people: blur every face preview before any screenshot
        # (the face/iris mode selector is hidden too: every run here is face mode)
        page.add_style_tag(content="img { filter: blur(9px); } .biometric-selector { display: none; }")
        user_agent = page.evaluate("navigator.userAgent")
        cores = page.evaluate("navigator.hardwareConcurrency")

        # --- ballot + trustee key ---
        tab(page, "ballot")
        page.get_by_placeholder(re.compile("Presidential", re.I)).fill("Browser run")
        page.get_by_role("button", name=re.compile("Add Candidate", re.I)).click()
        for i, name in enumerate(OPTIONS):
            page.get_by_placeholder(f"Candidate {i + 1}").fill(name)
        page.locator("form button[type=submit]").first.click()
        ok, text = wait_outcome(page)
        ballot_id = re.search(r"Ballot ID:\s*(\S+)", text).group(1) if ok else None
        log.append({"step": "create ballot", "ok": ok, "detail": text[:200]})
        shot(page, SHOTS / "1_ballot.png")
        if not ok:
            raise SystemExit(f"ballot creation failed: {text}")

        # --- enrollment ---
        creds = []
        for k, (name, enroll_img, _) in enumerate(voters):
            tab(page, "register")
            page.get_by_placeholder(re.compile("NID", re.I)).fill(f"browser-{random.getrandbits(48)}")
            page.get_by_placeholder(re.compile("Create a password", re.I)).fill(PASSWORD)
            page.locator("input[type=file]").set_input_files(str(enroll_img))
            with page.expect_download(timeout=TIMEOUT) as dl:
                page.locator("form button[type=submit]").click()
            path = SHOTS / f"credential_{k}.json"
            dl.value.save_as(path)
            creds.append(path)
            ok, text = wait_outcome(page)
            log.append({"step": f"enroll {name}", "ok": ok, "detail": text[:120]})
            if k == 0:
                shot(page, SHOTS / "2_register.png")

        def vote(cred, live_img, choice):
            tab(page, "vote")
            page.locator(".candidate-item", has_text=choice).click()
            files = page.locator("input[type=file]")
            files.nth(0).set_input_files(str(cred))
            page.get_by_placeholder(re.compile("Enter your password", re.I)).fill(PASSWORD)
            files.nth(1).set_input_files(str(live_img))
            t0 = time.perf_counter()
            page.locator("form button[type=submit]").click()
            ok, text = wait_outcome(page)
            return ok, text, 1000 * (time.perf_counter() - t0)

        # --- votes: each voter presents a different photo of themselves ---
        expected = {o: 0 for o in OPTIONS}
        for k, (name, _, live_img) in enumerate(voters):
            choice = OPTIONS[k % len(OPTIONS)]
            ok, text, wall = vote(creds[k], live_img, choice)
            log.append({"step": f"vote {name}", "ok": ok, "detail": text[:160], "wallMs": round(wall)})
            if ok:
                expected[choice] += 1
                walls.append(wall)
            if k == 0:
                shot(page, SHOTS / "3_vote.png")

        # --- impostor: voter 0's credential, another person's face ---
        ok, text, _ = vote(creds[0], impostor[1], OPTIONS[0])
        log.append({"step": f"impostor {impostor[0]} with voter 0's credential", "ok": ok, "detail": text[:160]})
        shot(page, SHOTS / "4_impostor.png")
        impostor_rejected = not ok

        # --- double vote: voter 1 again, genuine face ---
        ok, text, _ = vote(creds[1], voters[1][2], OPTIONS[0])
        log.append({"step": "double vote by voter 1", "ok": ok, "detail": text[:160]})
        double_rejected = not ok

        # --- tally ---
        tab(page, "tally")
        page.get_by_placeholder(re.compile("ballot ID", re.I)).fill(ballot_id)
        page.get_by_role("button", name=re.compile("Compute", re.I)).click()
        page.locator(".alert-success, .alert-error").first.wait_for(timeout=TIMEOUT)
        page.wait_for_timeout(1000)
        tally_text = page.locator(".card").last.inner_text()
        shot(page, SHOTS / "5_tally.png", until=".tally-container")
        browser.close()

    # timings[0] is the cold first vote (fetches the 13 MB proving key and
    # compiles the WASM witness generator); the rest are warm
    cold, warm = (timings[0], timings[1:]) if timings else ({}, [])
    phases = {}
    for key in ("merklePaths", "encryptBallot", "witness", "prove"):
        xs = [t[key] for t in warm if key in t]
        if xs:
            phases[key] = {"mean": round(statistics.mean(xs), 1), "ci95": round(ci95(xs), 1), "n": len(xs)}
    total = lambda t: sum(t.get(k, 0) for k in ("merklePaths", "encryptBallot", "witness", "prove"))
    totals = [total(t) for t in warm]
    tally_ok = all(re.search(rf"{o}\D+{expected[o]}\b", tally_text) for o in OPTIONS)
    result = {
        "date": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "browser": user_agent, "hardwareConcurrency": cores, "host": platform.processor(),
        "voters": N, "ballotId": ballot_id,
        "votesAccepted": len(walls), "impostorRejected": impostor_rejected,
        "doubleVoteRejected": double_rejected, "expectedTotals": expected,
        "tallyMatches": tally_ok, "tallyText": tally_text[:400],
        "phases": phases,
        "coldFirstVote": {k: round(v, 1) for k, v in cold.items()} | {"total": round(total(cold), 1)} if cold else None,
        # enroll_ms[0] is cold (fetches the enrollment proving key)
        "enrollProve": {"mean": round(statistics.mean(enroll_ms[1:]), 1), "ci95": round(ci95(enroll_ms[1:]), 1),
                        "n": len(enroll_ms) - 1} if len(enroll_ms) > 1 else None,
        "clientTotal": {"mean": round(statistics.mean(totals), 1), "ci95": round(ci95(totals), 1)} if totals else None,
        "submitToConfirmed": {"mean": round(statistics.mean(walls[1:]), 1), "ci95": round(ci95(walls[1:]), 1)} if len(walls) > 1 else None,
        "log": log,
    }
    (OUT / "browser_results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k not in ("log", "tallyText")}, indent=2))
    for entry in log:
        print(("OK  " if entry["ok"] else "--  ") + entry["step"] + ": " + entry["detail"].replace("\n", " ")[:110])


if __name__ == "__main__":
    main()
