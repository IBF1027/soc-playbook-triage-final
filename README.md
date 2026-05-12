# soc-playbook-triage-final

# SOC Ticket Triage Automation Tool v1.0

Rule-based SOC ticket triage pipeline with MITRE ATT&CK enrichment, CVSS risk scoring, and a live analyst dashboard.

Course: SDS 300 / SCS 400 1H - Dr. Burns | Author: Isaac Foster | May 2026


---

## What It Does

Tier-1 SOC analysts receive hundreds of alerts per shift. This tool automates the initial enrichment and triage recommendation for each incoming ticket so analysts spend time on real threats, not noise.

For every ticket in the input CSV the pipeline:

1. Validates the schema (12 required fields)
2. Calculates a CVSS V3.0-aligned risk score
3. Enriches each ticket with MITRE ATT&CK tactic, technique ID, CVE references, and numbered playbook steps
4. Applies a 4x3 severity x confidence decision matrix to produce: Escalate / Investigate / Close
5. Validates recommendations against ground-truth labels and reports accuracy, FP rate, and critical FN rate
6. Writes results to output/results.csv and a summary to output/summary_report.txt

A safety override ensures no CRITICAL-severity ticket can ever be recommended to Close.

---

## How to Run

Requirements: Python 3.10+ - standard library only, no pip install required.

    git clone https://github.com/IBF1027/soc-playbook-triage-final
    cd soc-playbook-triage-final
    python main.py --input demo/tickets.csv  (the 20 ticket dataset, in folder it is within data as tickets.csv.numbers, appears as tickets.csv within github)

Output:

    output/results.csv        - enriched dataset, one row per ticket
    output/summary_report.txt - accuracy metrics and decision breakdown
    output/execution.log      -
