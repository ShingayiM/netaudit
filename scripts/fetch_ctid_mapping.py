"""One-time helper: downloads the Center for Threat-Informed Defense's archived
'Mapping ATT&CK to CVE for Impact' CSV and converts it to the
{"CVE-xxxx-xxxx": ["Txxxx", ...]} format NetAudit reads from data/cve_attack_mapping.json.

This dataset (https://github.com/center-for-threat-informed-defense/attack_to_cve) is
archived and was last updated in 2021, so it only covers CVEs known at that time, but it is
real hand-reviewed mapping data rather than a guess. Run this once; re-run later if you find
a more current replacement (the project's successor, Mappings Explorer, does not currently
publish an equivalent flat per-CVE file: https://center-for-threat-informed-defense.github.io/mappings-explorer/).

Usage: python scripts/fetch_ctid_mapping.py
"""
import csv
import io
import json
import os
import re
import sys

import requests

URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/"
       "attack_to_cve/master/Att%26ckToCveMappings.csv")
OUT = os.path.join(os.path.dirname(__file__), "..", "data", "cve_attack_mapping.json")
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def main():
    print(f"Downloading {URL} ...")
    try:
        r = requests.get(URL, timeout=60)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"Download failed: {e}\nThe file may have moved; check "
              "https://github.com/center-for-threat-informed-defense/attack_to_cve")
        sys.exit(1)
    text = r.text.lstrip("\ufeff")  # the file starts with a UTF-8 BOM
    reader = csv.DictReader(io.StringIO(text))
    mapping = {}
    for row in reader:
        cve = (row.get("CVE ID") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        techs = set()
        for col in ("Primary Impact", "Secondary Impact", "Exploitation Technique", "Uncategorized"):
            techs.update(TECH_RE.findall(row.get(col) or ""))
        if techs:
            mapping[cve] = sorted(techs)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(mapping, open(OUT, "w"), indent=1)
    print(f"Wrote {len(mapping)} CVE mappings to {OUT}")
    print("Coverage is limited to CVEs published before 2021; NetAudit falls back to its "
          "keyword heuristic for any CVE not in this file.")


if __name__ == "__main__":
    main()
