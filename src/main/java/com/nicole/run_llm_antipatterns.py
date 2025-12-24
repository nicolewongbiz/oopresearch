#!/usr/bin/env python3

import json
import csv
from openai import OpenAI

INPUT_JSON = "llm_candidates.json"
OUTPUT_CSV = "oop_antipattern_results.csv"
MODEL = "gpt-4o-mini"

client = OpenAI()

GATE_QUESTIONS = {
    "ImproperPolymorphism": "Is this behavior better expressed using polymorphism instead of conditionals?",
    "EnumMisuse": "Is this enum being used to encode behavior instead of data?",
    "RedundantOverride": "Is this override unnecessary or redundant?",
    "MissingInheritance": "Do these classes share the same responsibility and need a common abstraction?",
    "RedundantInheritance": "Is this subclass conceptually unnecessary?",
    "LSP": "Does this inheritance violate the Liskov Substitution Principle?"
}

def llm_gate(antipattern, payload):
    prompt = f"""
{json.dumps(payload)}
Question: {GATE_QUESTIONS.get(antipattern, "Is this a valid issue?")}
Answer YES or NO only.
"""
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=1
    )
    return r.choices[0].message.content.strip().upper()

def llm_explain(antipattern, payload):
    prompt = f"""
Explain briefly why this is a {antipattern} antipattern.

{json.dumps(payload)}

Return JSON:
{{ "details": "..." }}
"""
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=80
    )
    try:
        return json.loads(r.choices[0].message.content)["details"]
    except Exception:
        return r.choices[0].message.content

# ----------------- pipeline 

with open(INPUT_JSON) as f:
    candidates = json.load(f)

# Deduplicate candidate
unique_keys = {}
for entry in candidates:
    key = (
        entry.get("antipattern", ""),
        entry.get("class", ""),
        entry.get("method", ""),
        entry.get("details", "")
    )
    if key not in unique_keys:
        unique_keys[key] = []
    unique_keys[key].append(entry)  # Keep track of all duplicates

# Prepare CSV
with open(OUTPUT_CSV, "w", newline="") as out:
    writer = csv.writer(out, quoting=csv.QUOTE_ALL)
    writer.writerow(["Student", "Class", "Method", "Antipattern", "Details"])

    # Iterate over unique issues
    for key, duplicates in unique_keys.items():
        antipattern = key[0]
        representative_entry = duplicates[0]  # Just pick one for LLM
        verdict = llm_gate(antipattern, representative_entry)

        if verdict != "YES":
            continue

        details = llm_explain(antipattern, representative_entry)

        # Write a row for all duplicates
        for entry in duplicates:
            writer.writerow([
                entry.get("student", ""),
                entry.get("class", ""),
                entry.get("method", ""),
                antipattern,
                details
            ])

print("LLM verification complete. Results written to", OUTPUT_CSV)