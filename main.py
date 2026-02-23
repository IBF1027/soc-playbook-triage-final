"""
Rule-Based SOC Ticket Triage Automation Tool (MVP)
===================================================
Usage:  python main.py --input data/tickets.csv
Output: output/results.csv  |  output/summary_report.txt

Pipeline stages
---------------
1. Data Loader          - reads CSV, halts on file error
2. Schema Validator     - enforces required columns and types
3. Preprocessor         - normalises fields, derives confidence band
4. Risk Scoring Engine  - CVSS-aligned risk score
5. Enrichment Engine    - maps alert type + indicators to MITRE, CVE, playbook
6. Decision Engine      - triage decision from risk matrix
7. Validation Module    - accuracy, FP rate, FN rate vs Expected_Action
8. Output Generator     - results.csv + summary_report.txt
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_COLUMNS = [
    "Ticket_ID", "Event_Time", "Alert_Source", "Alert_Type",
    "Detection_Tool", "Severity", "Confidence_Level",
    "Affected_Asset", "User_Role", "Indicators_Present",
    "Short_Description", "Expected_Action",
]

VALID_SEVERITIES   = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_ROLES        = {"Staff", "Admin", "Service"}
RULES_PATH         = os.path.join(os.path.dirname(__file__), "config", "rules.json")
OUTPUT_DIR         = os.path.join(os.path.dirname(__file__), "output")
MISSING_THRESHOLD  = 0.05   # 5 % max missing values in critical fields
CRITICAL_FIELDS    = ["Alert_Type", "Severity", "Short_Description"]


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log_path = os.path.join(OUTPUT_DIR, "execution.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode="w"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("soc_triage")


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1 — DATA LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_tickets(path: str, log) -> list[dict]:
    """Read CSV input file and return list of raw ticket dicts."""
    log.info(f"[Stage 1] Loading tickets from: {path}")
    if not os.path.exists(path):
        log.error(f"Input file not found: {path}")
        sys.exit(1)

    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            tickets = [row for row in reader]
    except Exception as e:
        log.error(f"Failed to read CSV: {e}")
        sys.exit(1)

    if not tickets:
        log.error("Input file is empty or contains no data rows.")
        sys.exit(1)

    log.info(f"  Loaded {len(tickets)} tickets from CSV.")
    return tickets


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2 — SCHEMA VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

def validate_schema(tickets: list[dict], log) -> None:
    """
    Check 1 : All required columns present (100 % threshold).
    Check 2 : Critical fields below 5 % missing value rate.
    Check 3 : Confidence_Level must be numeric 0–100.
    Check 4 : Severity must be one of CRITICAL / HIGH / MEDIUM / LOW.
    Halts pipeline execution on any failure.
    """
    log.info("[Stage 2] Validating schema...")
    errors = []

    # — Column presence check ———————————————————————————————————————————
    existing_cols = set(tickets[0].keys())
    missing_cols  = [c for c in REQUIRED_COLUMNS if c not in existing_cols]
    if missing_cols:
        errors.append(f"Missing required columns: {missing_cols}")

    if errors:
        for e in errors:
            log.error(f"  SCHEMA FAILURE: {e}")
        log.error("Pipeline halted due to schema validation failure.")
        sys.exit(1)

    total = len(tickets)

    # — Missing value check on critical fields ——————————————————————————
    for field in CRITICAL_FIELDS:
        missing_count = sum(1 for t in tickets if not t.get(field, "").strip())
        rate = missing_count / total
        if rate > MISSING_THRESHOLD:
            errors.append(
                f"Field '{field}' has {missing_count}/{total} missing values "
                f"({rate:.1%}) — exceeds 5% threshold."
            )

    # — Type validation: Confidence_Level ——————————————————————————————
    bad_confidence = []
    for t in tickets:
        val = t.get("Confidence_Level", "")
        try:
            n = int(val)
            if not (0 <= n <= 100):
                raise ValueError
        except (ValueError, TypeError):
            bad_confidence.append(t.get("Ticket_ID", "?"))
    if bad_confidence:
        errors.append(f"Confidence_Level out of range [0-100] for tickets: {bad_confidence[:5]} ...")

    # — Severity value check ————————————————————————————————————————————
    bad_severity = [
        t.get("Ticket_ID") for t in tickets
        if t.get("Severity", "").upper() not in VALID_SEVERITIES
    ]
    if bad_severity:
        errors.append(f"Invalid Severity values for tickets: {bad_severity[:5]} ...")

    if errors:
        for e in errors:
            log.error(f"  VALIDATION FAILURE: {e}")
        log.error("Pipeline halted due to data validation failure.")
        sys.exit(1)

    log.info(f"  Schema validation passed. {total} tickets ready for processing.")


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3 — PREPROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

def preprocess(tickets: list[dict], log) -> list[dict]:
    """
    - Normalise Severity and User_Role to consistent case.
    - Derive Confidence_Band from Confidence_Level.
    - Strip whitespace from all string fields.
    - Handle missing optional fields gracefully.
    """
    log.info("[Stage 3] Preprocessing tickets...")

    conf_bands = {"HIGH": (75, 100), "MEDIUM": (40, 74), "LOW": (0, 39)}

    def get_confidence_band(level: int) -> str:
        for band, (lo, hi) in conf_bands.items():
            if lo <= level <= hi:
                return band
        return "LOW"

    for t in tickets:
        # Normalise string fields
        for col in REQUIRED_COLUMNS:
            t[col] = t.get(col, "").strip()

        # Normalise severity to uppercase
        t["Severity"] = t["Severity"].upper()

        # Normalise User_Role to title case
        t["User_Role"] = t["User_Role"].strip().title()
        if t["User_Role"] not in VALID_ROLES:
            t["User_Role"] = "Staff"

        # Derive Confidence_Band
        try:
            conf = int(t["Confidence_Level"])
        except (ValueError, TypeError):
            conf = 0
        t["Confidence_Level_Int"] = conf
        t["Confidence_Band"] = get_confidence_band(conf)

    log.info(f"  Preprocessing complete. Confidence bands assigned.")
    return tickets


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4 — RISK SCORING ENGINE  (CVSS V3.0 aligned)
# ─────────────────────────────────────────────────────────────────────────────

def score_risk(tickets: list[dict], rules: dict, log) -> list[dict]:
    """
    Risk_Score = severity_base_score × confidence_multiplier
    CVSS V3.0 bands:
      CRITICAL : 9.0–10.0
      HIGH     : 7.0–8.9
      MEDIUM   : 4.0–6.9
      LOW      : 0.0–3.9
    """
    log.info("[Stage 4] Calculating risk scores (CVSS V3.0)...")

    sev_scores  = rules["risk_scoring"]["severity_base_score"]
    conf_mult   = rules["risk_scoring"]["confidence_multiplier"]

    for t in tickets:
        base = sev_scores.get(t["Severity"], 2.0)
        mult = conf_mult.get(t["Confidence_Band"], 0.5)
        t["Risk_Score"] = round(base * mult, 2)

    log.info("  Risk scores assigned.")
    return tickets


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5 — ENRICHMENT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def enrich_tickets(tickets: list[dict], rules: dict, log) -> list[dict]:
    """
    For each ticket:
    1. Match Alert_Type to its playbook definition.
    2. Scan Indicators_Present for keyword matches to select the specific rule.
    3. Enrich the ticket with MITRE Tactic, Technique, CVE, context,
       containment action, and full playbook steps.
    Falls back to alert-type defaults when no indicator keyword matches.
    """
    log.info("[Stage 5] Enriching tickets with MITRE, CVE, and playbook data...")

    alert_rules  = rules["alert_types"]
    enriched     = 0
    fallback     = 0
    unrecognised = 0

    for t in tickets:
        alert_type = t.get("Alert_Type", "").strip()
        indicators = t.get("Indicators_Present", "").lower()

        if alert_type not in alert_rules:
            # Unrecognised alert type — apply safe defaults
            t["Category_Label"]       = "Unknown"
            t["MITRE_Tactic"]         = "Unknown"
            t["MITRE_Technique"]      = "Unknown"
            t["Possible_CVE"]         = "N/A"
            t["Enrichment_Context"]   = "Alert type not recognised by rule engine. Manual analyst review required."
            t["Immediate_Containment"] = "Manual review required."
            t["Playbook_Steps"]       = "1. Manually review ticket and assign to senior analyst."
            unrecognised += 1
            continue

        atype_def     = alert_rules[alert_type]
        indicator_rules = atype_def.get("indicator_rules", [])
        matched_rule  = None

        # Keyword match: find first indicator rule whose keywords appear in indicators
        for rule in indicator_rules:
            if any(kw in indicators for kw in rule["match_keywords"]):
                matched_rule = rule
                break

        if matched_rule:
            enriched += 1
        else:
            # Fallback to first rule in list (most severe) for this alert type
            matched_rule = indicator_rules[0] if indicator_rules else {}
            fallback += 1

        t["Category_Label"]        = atype_def.get("category_label", alert_type)
        t["MITRE_Tactic"]          = atype_def.get("mitre_tactic", "Unknown")
        t["MITRE_Technique"]       = matched_rule.get("mitre_technique", atype_def.get("default_mitre_technique", "Unknown"))
        t["Possible_CVE"]          = matched_rule.get("possible_cve", "N/A")
        t["Enrichment_Context"]    = matched_rule.get("enrichment_context", "No enrichment context available.")
        t["Immediate_Containment"] = matched_rule.get("immediate_containment", "No containment action defined.")
        t["Playbook_Steps"]        = "\n".join(matched_rule.get("playbook_steps", ["No steps defined."]))

    log.info(f"  Enrichment complete: {enriched} keyword-matched, {fallback} fallback, {unrecognised} unrecognised.")
    return tickets


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 6 — DECISION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def make_decisions(tickets: list[dict], rules: dict, log) -> list[dict]:
    """
    Apply triage decision matrix:
      rows = Severity (CRITICAL / HIGH / MEDIUM / LOW)
      cols = Confidence_Band (HIGH / MEDIUM / LOW)
    Outputs one of: Escalate | Investigate | Close - False Positive | Close - Resolved
    """
    log.info("[Stage 6] Applying triage decision rules...")

    matrix = rules["triage_decision_matrix"]

    # Keywords in Indicators_Present that confirm a verified benign resolution.
    # "Resolved" = a real event that was self-contained and closed cleanly.
    # "False Positive" = the alert was noise (no real event occurred).
    resolved_keywords = [
        "quarantine successful",
        "user confirmed",
        "known device",
        "routine backup",
        "approved classification",
        "internal recipient",
        "known destination",
    ]

    for t in tickets:
        sev  = t.get("Severity", "LOW")
        band = t.get("Confidence_Band", "LOW")
        decision = matrix.get(sev, {}).get(band, "Investigate")

        indicators = t.get("Indicators_Present", "").lower()

        # Override: LOW severity + confirmed benign resolution keyword in indicators
        # → promote from False Positive to Resolved (a real but self-contained event).
        if sev == "LOW" and any(kw in indicators for kw in resolved_keywords):
            decision = "Close - Resolved"

        t["Recommended_Action"] = decision

    log.info("  Triage decisions assigned.")
    return tickets


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 7 — VALIDATION MODULE
# ─────────────────────────────────────────────────────────────────────────────

def validate_decisions(tickets: list[dict], log) -> dict:
    """
    Compare Recommended_Action against Expected_Action (ground truth label).
    Computes:
      - Overall accuracy %
      - False Positive rate  (system said Escalate/Investigate; truth was Close)
      - False Negative rate  (system said Close; truth was Escalate/Investigate)
    Returns a metrics dict and stamps each ticket with Decision_Correct.
    """
    log.info("[Stage 7] Validating decisions against expected actions...")

    total = len(tickets)
    correct = 0
    false_positives = 0   # system over-triaged (recommended action > expected)
    false_negatives = 0   # system under-triaged (recommended action < expected)
    wrong_tickets   = []

    action_rank = {
        "Escalate": 3,
        "Investigate": 2,
        "Close - Resolved": 1,
        "Close - False Positive": 0,
    }

    for t in tickets:
        rec = t.get("Recommended_Action", "")
        exp = t.get("Expected_Action", "")

        match = rec.strip().lower() == exp.strip().lower()
        t["Decision_Correct"] = "YES" if match else "NO"

        if match:
            correct += 1
        else:
            wrong_tickets.append({
                "Ticket_ID": t["Ticket_ID"],
                "Expected":  exp,
                "Got":       rec,
            })
            rec_rank = action_rank.get(rec, 1)
            exp_rank = action_rank.get(exp, 1)
            if rec_rank > exp_rank:
                false_positives += 1   # over-triaged
            else:
                false_negatives += 1   # under-triaged

    accuracy   = (correct / total) * 100
    fp_rate    = (false_positives / total) * 100
    fn_rate    = (false_negatives / total) * 100

    metrics = {
        "total_tickets":   total,
        "correct":         correct,
        "incorrect":       total - correct,
        "accuracy_pct":    round(accuracy, 2),
        "fp_rate_pct":     round(fp_rate, 2),
        "fn_rate_pct":     round(fn_rate, 2),
        "wrong_tickets":   wrong_tickets,
    }

    log.info(f"  Accuracy:      {accuracy:.1f}%  ({correct}/{total} correct)")
    log.info(f"  FP rate:       {fp_rate:.1f}%  (over-triaged)")
    log.info(f"  FN rate:       {fn_rate:.1f}%  (under-triaged)")

    if wrong_tickets:
        log.info(f"  Mismatches:")
        for w in wrong_tickets:
            log.info(f"    Ticket {w['Ticket_ID']} | Expected: {w['Expected']} | Got: {w['Got']}")

    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 8 — OUTPUT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_FIELDS = [
    # — Original ticket fields —
    "Ticket_ID", "Event_Time", "Alert_Source", "Alert_Type", "Detection_Tool",
    "Severity", "Confidence_Level", "Confidence_Band", "Affected_Asset",
    "User_Role", "Indicators_Present", "Short_Description",
    # — Enriched fields (added by pipeline) —
    "Category_Label", "Risk_Score",
    "MITRE_Tactic", "MITRE_Technique", "Possible_CVE",
    "Enrichment_Context", "Immediate_Containment", "Playbook_Steps",
    # — Decision fields —
    "Recommended_Action", "Expected_Action", "Decision_Correct",
]

def write_results(tickets: list[dict], metrics: dict, runtime: float, log) -> None:
    """Write enriched results CSV and a plain-text summary report."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # — results.csv ————————————————————————————————————————————————————
    results_path = os.path.join(OUTPUT_DIR, "results.csv")
    with open(results_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(tickets)
    log.info(f"[Stage 8] Results written to: {results_path}")

    # — Action distribution ———————————————————————————————————————————
    action_counts: dict[str, int] = {}
    for t in tickets:
        a = t.get("Recommended_Action", "Unknown")
        action_counts[a] = action_counts.get(a, 0) + 1

    type_counts: dict[str, int] = {}
    for t in tickets:
        a = t.get("Category_Label", "Unknown")
        type_counts[a] = type_counts.get(a, 0) + 1

    sev_counts: dict[str, int] = {}
    for t in tickets:
        s = t.get("Severity", "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    # — summary_report.txt ————————————————————————————————————————————
    report_path = os.path.join(OUTPUT_DIR, "summary_report.txt")
    run_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sep = "=" * 60

    lines = [
        sep,
        "  SOC TICKET TRIAGE — EXECUTION SUMMARY REPORT",
        sep,
        f"  Run timestamp : {run_ts}",
        f"  Runtime       : {runtime:.2f} seconds",
        "",
        "── DATASET OVERVIEW ─────────────────────────────────────",
        f"  Total tickets processed : {metrics['total_tickets']}",
        "",
        "  Tickets by alert category:",
    ]
    for cat, cnt in sorted(type_counts.items()):
        lines.append(f"    {cat:<30} {cnt:>4} tickets")

    lines += [
        "",
        "  Tickets by severity:",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = sev_counts.get(sev, 0)
        lines.append(f"    {sev:<30} {cnt:>4} tickets")

    lines += [
        "",
        "── TRIAGE DECISION DISTRIBUTION ────────────────────────",
    ]
    for action, cnt in sorted(action_counts.items()):
        lines.append(f"    {action:<35} {cnt:>4} tickets")

    lines += [
        "",
        "── VALIDATION METRICS ──────────────────────────────────",
        f"  Correct decisions  : {metrics['correct']} / {metrics['total_tickets']}",
        f"  Decision accuracy  : {metrics['accuracy_pct']}%",
        f"  False positive rate: {metrics['fp_rate_pct']}%  (over-triaged)",
        f"  False negative rate: {metrics['fn_rate_pct']}%  (under-triaged)",
    ]

    target_met = "✓ TARGET MET" if metrics["accuracy_pct"] >= 95.0 else "✗ BELOW 95% TARGET"
    lines.append(f"  Accuracy target    : >95%  →  {target_met}")

    if metrics["wrong_tickets"]:
        lines += ["", "  Mismatch detail:"]
        for w in metrics["wrong_tickets"]:
            lines.append(f"    Ticket {w['Ticket_ID']:<8} | Expected: {w['Expected']:<30} | Got: {w['Got']}")

    lines += [
        "",
        "── PIPELINE STAGE COMPLETION ───────────────────────────",
        "  [✓] Stage 1 - Data Loader",
        "  [✓] Stage 2 - Schema Validator",
        "  [✓] Stage 3 - Preprocessor",
        "  [✓] Stage 4 - Risk Scoring Engine (CVSS V3.0)",
        "  [✓] Stage 5 - Enrichment Engine (MITRE / CVE / Playbook)",
        "  [✓] Stage 6 - Decision Engine (Triage Matrix)",
        "  [✓] Stage 7 - Validation Module",
        "  [✓] Stage 8 - Output Generator",
        "",
        sep,
        "  Note: This tool is a Tier-1 decision support aid.",
        "  Final triage decisions remain under human analyst control.",
        sep,
    ]

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log.info(f"  Summary report written to: {report_path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def load_rules(log) -> dict:
    if not os.path.exists(RULES_PATH):
        log.error(f"Rules file not found: {RULES_PATH}")
        sys.exit(1)
    try:
        with open(RULES_PATH, encoding="utf-8") as f:
            rules = json.load(f)
        log.info(f"  Rules loaded from: {RULES_PATH}")
        return rules
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse rules.json: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Rule-Based SOC Ticket Triage Pipeline"
    )
    parser.add_argument("--input", required=True, help="Path to input tickets CSV")
    args = parser.parse_args()

    log = setup_logging()
    start = time.time()

    log.info("=" * 60)
    log.info("  SOC TICKET TRIAGE PIPELINE — STARTING")
    log.info("=" * 60)

    rules   = load_rules(log)
    tickets = load_tickets(args.input, log)
    validate_schema(tickets, log)
    tickets = preprocess(tickets, log)
    tickets = score_risk(tickets, rules, log)
    tickets = enrich_tickets(tickets, rules, log)
    tickets = make_decisions(tickets, rules, log)
    metrics = validate_decisions(tickets, log)

    runtime = time.time() - start
    write_results(tickets, metrics, runtime, log)

    log.info("=" * 60)
    log.info(f"  PIPELINE COMPLETE  |  Runtime: {runtime:.2f}s")
    log.info(f"  Accuracy: {metrics['accuracy_pct']}%  |  Tickets: {metrics['total_tickets']}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
