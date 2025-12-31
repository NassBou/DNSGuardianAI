#!/usr/bin/env python3
# test_detection_v2.py  — v2 CLI with v1-style batch evaluation
# Cloud mode: concurrent; Local mode: sequential

import os
import sys
import csv
import re
import ipaddress
import random
import contextlib
import asyncio
import inspect
import json
import time
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any, Callable

# Local imports
from settings import config, get_llm_settings
from domain_analyser import DomainAnalyser as _Analyser  # UPDATED

# ---------- Defaults (match v1) ----------
DEFAULT_CSV = os.path.join(os.path.dirname(__file__), "cleaned.csv")
_logging_cfg = config.get("logging", {}) if isinstance(config, dict) else {}
DEFAULT_LOG_DIR = _logging_cfg.get("log_dir", "logs")
DEFAULT_ENABLE_LOGGING = bool(_logging_cfg.get("enable_logging", True))
DEFAULT_ENABLE_REASONING = bool(_logging_cfg.get("enable_reasoning_log", False))

# -------- V1-style constants --------
URL_COLS = {"url", "domain", "host", "link"}
LABEL_COLS = {"label", "status", "class", "target", "is_malicious", "malicious"}
TEXT_LABEL_MAP = {
    "1": 1, "malicious": 1, "phishing": 1, "likely phishing": 1, "spam": 1,
    "bad": 1, "blacklist": 1, "block": 1, "blocked": 1, "deny": 1, "denied": 1,
    "dangerous": 1, "true": 1, "yes": 1, "y": 1,
    "0": 0, "benign": 0, "legit": 0, "legitimate": 0, "clean": 0, "good": 0,
    "safe": 0, "whitelist": 0, "allow": 0, "allowed": 0, "false": 0, "no": 0, "n": 0
}
BLOCKY_WORDS = {
    "block", "blocked", "deny", "denied", "malicious", "phishing",
    "likely phishing", "suspicious", "dangerous", "blacklist", "blacklisted",
}
SAFE_WORDS = {"safe", "benign", "clean", "whitelist", "whitelisted", "allow", "allowed"}

# -------- Helpers / prompts --------
def _ask(prompt: str, default: Optional[str] = None, validator: Optional[Callable[[str], bool]] = None) -> str:
    if not sys.stdin.isatty():
        return default if default is not None else ""
    suffix = f" [{default}]" if default else ""
    while True:
        ans = input(f"{prompt}{suffix}: ").strip()
        if ans == "" and default is not None:
            ans = default
        if validator is None or validator(ans):
            return ans
        print("Invalid input, please try again.")

def _is_int(s: str) -> bool:
    try:
        int(s); return True
    except Exception:
        return False

def _is_pos_int(s: str) -> bool:
    try:
        return int(s) > 0
    except Exception:
        return False

def _syncify(x):
    return asyncio.run(x) if inspect.iscoroutine(x) else x  # v1 behavior for sequential paths

@contextlib.contextmanager
def suppress_output(enabled: bool):
    if not enabled:
        yield
        return
    saved_out, saved_err = sys.stdout, sys.stderr
    try:
        with open(os.devnull, "w") as devnull:
            sys.stdout = devnull
            sys.stderr = devnull
            yield
    finally:
        sys.stdout = saved_out
        sys.stderr = saved_err

# -------- V1-style parsing / normalization --------
def _looks_like_ipv6_hostpiece(s: str) -> bool:
    return s.startswith("[") or s.count(":") >= 2

def _strip_scheme(s: str) -> str:
    return re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', s)

def _coerce_label(value: str) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s.replace(".", "", 1).isdigit() and s[0] in ("0", "1"):
        return 1 if s.startswith("1") else 0
    return TEXT_LABEL_MAP.get(s)

def _split_url_and_label(raw: str) -> Tuple[str, Optional[int]]:
    s = str(raw).strip().strip('"').strip("'")
    if "," in s:
        left, last = s.rsplit(",", 1)
        lab = _coerce_label(last)
        if lab is not None:
            return left.strip(), lab
    return s, None

def normalize_to_domain(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    s = str(url_or_host).strip().strip('"').strip("'")
    s = _strip_scheme(s)
    if "/" in s:
        s = s.split("/", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[-1]
    host = s
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            ipv6 = host[1:end]
            try:
                ipaddress.ip_address(ipv6)
                return ipv6.lower()
            except Exception:
                return ""
        else:
            return ""
    if _looks_like_ipv6_hostpiece(host):
        parts = host.rsplit(":", 1)
        candidate = parts[0] if (len(parts) == 2 and parts[1].isdigit()) else host
        try:
            ipaddress.ip_address(candidate)
            return candidate.lower()
        except Exception:
            pass
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    if not re.fullmatch(r"[a-z0-9\-._~%]+", host):
        if not host or any(c.isspace() for c in host):
            return ""
    return host

def load_dataset(csv_path: str) -> List[Tuple[str, int]]:
    rows: List[Tuple[str, int]] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        peek = f.read(4096); f.seek(0)
        has_header = any(col in peek.lower() for col in URL_COLS | LABEL_COLS)
        if has_header:
            reader = csv.DictReader(f)
            cols = {c.lower(): c for c in (reader.fieldnames or [])}
            url_col = next((cols[c] for c in cols if c in URL_COLS), None)
            lab_col = next((cols[c] for c in cols if c in LABEL_COLS), None)
            if url_col and lab_col:
                for rec in reader:
                    url = (rec.get(url_col) or "").strip()
                    lab = _coerce_label(rec.get(lab_col))
                    if not url:
                        continue
                    if lab is None:
                        u2, l2 = _split_url_and_label(url)
                        if l2 is not None:
                            rows.append((u2, l2))
                    else:
                        rows.append((url, lab))
        else:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                if len(row) == 1:
                    u, l = _split_url_and_label(row[0])
                    if l is not None:
                        rows.append((u, l))
                else:
                    u = (row[0] or "").strip()
                    l = _coerce_label(row[1])
                    if l is not None:
                        rows.append((u, l))
    if not rows:
        raise ValueError("No labeled rows found in CSV.")
    dedup: Dict[str, int] = {}
    skipped = 0
    for u, l in rows:
        d = normalize_to_domain(u)
        if not d:
            skipped += 1
            continue
        dedup[d] = max(l, dedup.get(d, 0))
    if skipped:
        print(f"[INFO] Skipped {skipped} rows with invalid/empty domains after normalization.")
    return list(dedup.items())

def stratified_sample(items: List[Tuple[str, int]], n: int, seed: Optional[int]) -> List[Tuple[str, int]]:
    if seed is not None:
        random.seed(seed)
    if n >= len(items):
        return items[:]
    by_label: Dict[int, List[Tuple[str, int]]] = {0: [], 1: []}
    for d in items:
        by_label[d[1]].append(d)
    total = len(items)
    n1 = round(n * len(by_label[1]) / total) if total else 0
    n0 = n - n1
    sample = random.sample(by_label[1], min(n1, len(by_label[1]))) + \
             random.sample(by_label[0], min(n0, len(by_label[0])))
    random.shuffle(sample)
    return sample

def verdict_is_block(analysis: dict) -> bool:
    if not isinstance(analysis, dict):
        return False
    for key in ("verdict", "decision", "action", "result", "status"):
        val = analysis.get(key)
        if val is None:
            continue
        s = str(val).strip().lower()
        if any(w in s for w in BLOCKY_WORDS):
            return True
        if any(w in s for w in SAFE_WORDS):
            return False
    v = str(analysis.get("verdict", "")).lower()
    if v in ("allow", "block"):
        return v == "block"
    return False

# ------------------------------ Run Modes ------------------------------
def _run_single(analyser: _Analyser) -> None:
    domain = _ask("Enter a domain to analyze (e.g., example.com)", "")
    if not domain:
        print("No domain provided. Exiting.")
        return
    t0 = time.time()
    result = _syncify(analyser.analyse(domain))
    dt = (time.time() - t0) * 1000.0
    print("-" * 72)
    print(f"Domain: {domain}")
    print(f"Time: {dt:.1f} ms")
    print(f"Result: {result}")
    print("-" * 72)

def _report_and_write(
    y_true: List[int],
    y_pred: List[int],
    undetected: List[Tuple[str, str]],
    false_positives: List[Tuple[str, str]],
    log_path: str,
    llm_responses_path: str,
) -> None:
    # --- REPORT (v1 metrics) ---
    print("\n=== REPORT ===")
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y_true) if y_true else 0.0

    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"Accuracy: {accuracy:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
    print(f"Per-domain logs:\n- {log_path}\n- {llm_responses_path}")

    base_dir = os.path.dirname(__file__)
    fn_path = os.path.join(base_dir, "false_negatives.txt")
    fp_path = os.path.join(base_dir, "false_positives.txt")
    with open(fn_path, "w", encoding="utf-8") as f:
        f.write("domain,reason\n")
        for d, v in undetected:
            f.write(f"{d},{v}\n")
    with open(fp_path, "w", encoding="utf-8") as f:
        f.write("domain,reason\n")
        for d, v in false_positives:
            f.write(f"{d},{v}\n")
    print(f"Also wrote:\n- {fn_path}\n- {fp_path}")
    print("\nDone.\n")

def _run_batch_sequential(
    analyser: _Analyser,
    sampled: List[Tuple[str, int]],
    quiet: bool,
    log_path: str,
    llm_responses_path: str,
):
    undetected: List[Tuple[str, str]] = []
    false_positives: List[Tuple[str, str]] = []
    y_true: List[int] = []
    y_pred: List[int] = []
    
    with open(log_path, "w", encoding="utf-8") as log_f, open(llm_responses_path, "a", encoding="utf-8") as llm_f:
        llm_f.write("=== Raw LLM Responses (from analyser result) ===\n\n")
        for domain, label in sampled:
            t0 = time.perf_counter()
            try:
                with suppress_output(quiet):
                    result = _syncify(analyser.analyse(domain))
            except Exception as e:
                result = {"verdict": "Error", "reason": str(e), "source": "exception"}
            dur_ms = (time.perf_counter() - t0) * 1000.0

            blocked = verdict_is_block(result if isinstance(result, dict) else {})

            if label == 1 and not blocked:
                undetected.append((domain, str(result.get("reason") if isinstance(result, dict) else "")))
            if label == 0 and blocked:
                false_positives.append((domain, str(result.get("reason") if isinstance(result, dict) else "")))

            y_true.append(label)
            y_pred.append(1 if blocked else 0)

            # JSONL log
            if label == 1 and blocked:
                outcome = "TP"
            elif label == 0 and not blocked:
                outcome = "TN"
            elif label == 0 and blocked:
                outcome = "FP"
            else:
                outcome = "FN"

            json.dump({
                "domain": domain,
                "label": label,
                "outcome": outcome,
                "blocked": blocked,
                "latency_ms": round(dur_ms, 2),
                "verdict": result.get("verdict"),
                "score": result.get("score"),
                "llm_verdict": result.get("evidence", {}).get("llm_verdict"),
                "recent_domain": result.get("evidence", {}).get("recent_domain"),
                "san_verdict": result.get("evidence", {}).get("san_verdict"),
            }, log_f)
            log_f.write("\n")


            # Human-readable per-domain log
            ev = result.get("evidence", {})
            llm_f.write(
                f"Domain: {domain}\n"
                f"Label: {label}\n"
                f"Outcome: {outcome}\n"
                f"Final verdict: {result.get('verdict')}\n"
                f"Score: {result.get('score')}\n"
                f"LLM verdict: {ev.get('llm_verdict')}\n"
                f"Recent domain: {ev.get('recent_domain')}\n"
                f"SAN verdict: {ev.get('san_verdict')}\n"
                + "-" * 70 + "\n\n"
            )

    _report_and_write(y_true, y_pred, undetected, false_positives, log_path, llm_responses_path)

async def _run_batch_concurrent_async(
    analyser: _Analyser,
    sampled: List[Tuple[str, int]],
    quiet: bool,
    log_path: str,
    llm_responses_path: str,
    max_concurrency: int,
):
    """
    Concurrent version for cloud mode. Bounded by max_concurrency.
    Works whether analyser.analyse is async or sync.
    """
    sem = asyncio.Semaphore(max_concurrency)
    lock = asyncio.Lock()  # protect file writes and shared lists

    undetected: List[Tuple[str, str]] = []
    false_positives: List[Tuple[str, str]] = []
    y_true: List[int] = []
    y_pred: List[int] = []

    # Open files once; serialise writes via lock
    log_f = open(log_path, "w", encoding="utf-8")
    llm_f = open(llm_responses_path, "a", encoding="utf-8")
    llm_f.write("=== Raw LLM Responses (from analyser result) ===\n\n")

    async def run_one(domain: str, label: int):
        nonlocal undetected, false_positives, y_true, y_pred
        async with sem:
            t0 = time.perf_counter()
            try:
                res_candidate = analyser.analyse(domain)
                if inspect.iscoroutine(res_candidate):
                    if quiet:
                        with suppress_output(True):
                            result = await res_candidate
                    else:
                        result = await res_candidate
                else:
                    result = await asyncio.to_thread(lambda: _syncify(res_candidate))
            except Exception as e:
                result = {"verdict": "Error", "reason": str(e), "source": "exception"}
            dur_ms = (time.perf_counter() - t0) * 1000.0

            blocked = verdict_is_block(result if isinstance(result, dict) else {})

            async with lock:
                if label == 1 and not blocked:
                    undetected.append((domain, str(result.get("reason") if isinstance(result, dict) else "")))
                if label == 0 and blocked:
                    false_positives.append((domain, str(result.get("reason") if isinstance(result, dict) else "")))

                y_true.append(label)
                y_pred.append(1 if blocked else 0)

                # JSONL log
                json.dump({
                    "domain": domain,
                    "label": label,
                    "blocked": blocked,
                    "latency_ms": round(dur_ms, 2),
                    "result": result
                }, log_f)
                log_f.write("\n")

                # Human-readable per-domain log
                llm_f.write(f"Domain: {domain}\nLabel: {label}\nBlocked: {blocked}\nLatency (ms): {dur_ms:.2f}\n")
                llm_f.write("LLM/Analyser Result:\n")
                llm_f.write(json.dumps(result, ensure_ascii=False, indent=2))
                llm_f.write("\n" + "-" * 70 + "\n\n")

    tasks = [asyncio.create_task(run_one(domain, label)) for domain, label in sampled]
    await asyncio.gather(*tasks)

    log_f.close()
    llm_f.close()

    _report_and_write(y_true, y_pred, undetected, false_positives, log_path, llm_responses_path)

def _run_batch_v1_style(analyser: _Analyser, concurrent: bool, max_concurrency: int) -> None:
    sample_size_str = _ask("Sample size", "100", lambda s: s.isdigit() and int(s) > 0)
    stratify_str    = _ask("Stratify by class? (y/n)", "y", lambda s: s.lower() in {"y","n"}).lower()
    quiet_str       = _ask("Quiet mode (suppress analyser output)? (y/n)", "y", lambda s: s.lower() in {"y","n"}).lower()

    rows = load_dataset(DEFAULT_CSV)
    sample_size = min(int(sample_size_str or "100"), len(rows))
    stratify = stratify_str.startswith("y")
    quiet = quiet_str.startswith("y")
    sampled = stratified_sample(rows, sample_size, None) if stratify else random.sample(rows, sample_size)

    run_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_dir = os.path.dirname(__file__)
    log_path = os.path.join(base_dir, f"analyses-{run_ts}.jsonl")
    llm_responses_path = os.path.join(base_dir, f"llm_responses-{run_ts}.txt")

    print(f"\nLoaded {len(rows)} domains | Testing {len(sampled)} (stratify={stratify})")
    if concurrent:
        print(f"Cloud mode: concurrent processing with up to {max_concurrency} in flight...\n")
        asyncio.run(_run_batch_concurrent_async(
            analyser=analyser,
            sampled=sampled,
            quiet=quiet,
            log_path=log_path,
            llm_responses_path=llm_responses_path,
            max_concurrency=max_concurrency,
        ))
    else:
        print("Local mode: sequential processing, waiting for each LLM reply...\n")
        _run_batch_sequential(
            analyser=analyser,
            sampled=sampled,
            quiet=quiet,
            log_path=log_path,
            llm_responses_path=llm_responses_path,
        )

def main():
    print("=" * 72)
    print(" Domain Evaluator — V2 CLI (V1-style batch; cloud=concurrent)")
    print("=" * 72)

    llm_info = get_llm_settings()
    profiles = llm_info["profiles"]
    profiles_csv = "/".join(profiles)
    mode = _ask(f"LLM mode ({profiles_csv})", llm_info["profile"],
                lambda s: s.lower() in {p.lower() for p in profiles}).lower()

    llm_info = get_llm_settings(profile_choice=mode)
    model = llm_info["model"]
    api_url = llm_info["api_url"]
    api_key_env = llm_info["api_key_env"]

    api_key = os.environ.get(api_key_env)
    if (("openai.com" in api_url) or (".azure.com" in api_url)) and not api_key:
        try:
            from getpass import getpass
            api_key = getpass(f"Enter {api_key_env} (hidden): ")
        except Exception:
            api_key = _ask(f"Enter {api_key_env}", "")

    print(f"\nUsing LLM: {mode} -> {model} @ {api_url}\n")

    reason_str = _ask("Save LLM 'thinking' logs? (y/n)",
                      "y" if DEFAULT_ENABLE_REASONING else "n",
                      lambda s: s.lower() in {"y","n"}).lower()
    save_reason = reason_str.startswith("y")
    http_log_str = _ask("Enable HTTP + content logging? (y/n)",
                        "y" if DEFAULT_ENABLE_LOGGING else "n",
                        lambda s: s.lower() in {"y","n"}).lower()
    enable_http_logging = http_log_str.startswith("y")
    log_dir = _ask("Log directory", DEFAULT_LOG_DIR) or DEFAULT_LOG_DIR
    os.makedirs(log_dir, exist_ok=True)

    threshold_str = _ask("Block threshold (int)", "1", _is_int)
    threshold = int(threshold_str)

    mode_choice = _ask("Run mode (single/batch)", "batch", lambda s: s.lower() in {"single","batch"}).lower()

    # UPDATED: build DomainAnalyser, disable list persistence, but keep your logging toggles
    analyser = _Analyser(
        model=model,
        api_url=api_url,
        block_score=threshold,
        use_blacklists=False,              # 🔥 demo mode: no blacklist writes/reads
        enable_logging=enable_http_logging,
        enable_reasoning_log=save_reason,
        log_dir=log_dir,
        api_key=api_key,
        timeout=60.0,
    )

    is_cloud = (mode.lower() == "cloud")
    max_conc = 8
    if is_cloud:
        mc_str = _ask("Max concurrency for cloud mode", str(max_conc), _is_pos_int)
        max_conc = int(mc_str)

    if mode_choice == "single":
        _run_single(analyser)
    else:
        _run_batch_v1_style(analyser, concurrent=is_cloud, max_concurrency=max_conc)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
