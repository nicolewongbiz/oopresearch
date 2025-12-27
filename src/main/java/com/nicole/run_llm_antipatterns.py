#!/usr/bin/env python3

import json
import csv
import time
from datetime import datetime
from openai import OpenAI

# ================= CONFIG =================
INPUT_JSON = "llm_candidates.json"
OUTPUT_CSV = "oop_antipattern_results.csv"
STATS_FILE = "llm_analysis_statistics.txt"
MODEL = "gpt-4o-mini"

client = OpenAI()

# ================= PROMPTS =================
ANTIPATTERN_PROMPTS = {
    "SwitchComplexity": """Analyze this switch statement evidence:
{evidence}

Guidelines:
- Switches with 1-3 simple cases → usually NO
- Switches with complex logic → likely YES
- State machines or factory patterns may be acceptable

Question: Is this switch complexity problematic enough to warrant refactoring with polymorphism?

Answer: YES/NO: [brief explanation]""",

    "RedundantOverride": """Analyze this method override:
{evidence}

Guidelines:
- Identical to parent → likely YES
- Adds logging/validation → usually NO

Question: Is this override truly redundant with no purpose?

Answer: YES/NO: [brief explanation]""",

    "TypeChecking": """Analyze this type checking:
{evidence}

Guidelines:
- Simple dispatch → usually NO
- Complex logic per type → likely YES

Question: Should this type checking be replaced with polymorphism?

Answer: YES/NO: [brief explanation]""",

    "InstanceOfCheck": """Analyze this instanceof check:
{evidence}

Guidelines:
- Validation/null checks → usually NO
- Behavior dispatch → likely YES

Question: Does this instanceof indicate missing polymorphism?

Answer: YES/NO: [brief explanation]""",

    "DefectiveEmptyOverride": """Analyze this empty override:
{evidence}

Guidelines:
- Disables important functionality → YES
- Trivial/no-op parent → maybe NO

Question: Does this empty override violate Liskov Substitution Principle?

Answer: YES/NO: [brief explanation]""",

    "PotentialMissingInheritance": """Analyze this potential missing inheritance:
{evidence}

Guidelines:
- Identical/similar methods across classes → likely YES
- Only trivial methods → usually NO

Question: Should these classes be refactored with a common superclass/interface?

Answer: YES/NO: [brief explanation]""",

    "RedundantInheritance": """Analyze this redundant inheritance:
{evidence}

Guidelines:
- Inherits but doesn't use parent features → likely YES

Question: Is this inheritance redundant/unnecessary?

Answer: YES/NO: [brief explanation]""",

    "DEFAULT": """Analyze this potential antipattern:
{evidence}

Be conservative; only flag clear OOP violations.
When in doubt, answer NO.

Question: Is this a legitimate antipattern that needs fixing?

Answer: YES/NO: [brief explanation]"""
}

# ================= FUNCTIONS =================

def normalize_string(s):
    """Normalize strings for deduplication."""
    return (s or "").strip().lower()

def normalize_evidence(e):
    """Normalize evidence JSON for deduplication."""
    if not e:
        return {}
    return e  # Keep full evidence as-is; only order/sorting matters in json.dumps with sort_keys

def analyze_candidate(entry):
    """Call LLM and parse verdict/explanation."""
    antipattern = entry.get("antipattern", "")
    evidence = entry.get("evidence", {})

    prompt_template = ANTIPATTERN_PROMPTS.get(antipattern, ANTIPATTERN_PROMPTS["DEFAULT"])
    prompt = prompt_template.format(evidence=json.dumps(evidence, indent=2))

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=100
        )

        result = response.choices[0].message.content.strip()

        if result.upper().startswith("YES:"):
            verdict = "YES"
            explanation = result[4:].strip()
        elif result.upper().startswith("NO:"):
            verdict = "NO"
            explanation = result[3:].strip()
        else:
            upper_result = result.upper()
            if "YES" in upper_result:
                verdict = "YES"
            elif "NO" in upper_result:
                verdict = "NO"
            else:
                verdict = "UNKNOWN"
            explanation = result

        return {"verdict": verdict, "explanation": explanation, "raw_response": result}

    except Exception as e:
        print(f"Error analyzing candidate: {e}")
        return {"verdict": "ERROR", "explanation": f"Analysis failed: {e}", "raw_response": ""}

def deduplicate_candidates(candidates):
    """Deduplicate while keeping all original entries mapped."""
    seen = {}
    unique_candidates = []

    for entry in candidates:
        key = (
            normalize_string(entry.get("class")),
            normalize_string(entry.get("method")),
            normalize_string(entry.get("antipattern")),
            json.dumps(normalize_evidence(entry.get("evidence", {})), sort_keys=True)
        )

        if key not in seen:
            seen[key] = [entry]
            unique_candidates.append(entry)
        else:
            seen[key].append(entry)

    return unique_candidates, seen

def write_statistics(stats, confirmed_by_type, total_candidates, unique_candidates, duplicates_map, elapsed_time):
    """Write stats reflecting totals across all original candidates (pre-deduplication)."""
    # Initialize totals
    total_mapped = total_candidates
    yes_mapped = 0
    no_mapped = 0
    error_mapped = 0

    # Map unique verdicts back to all original entries
    for key, original_entries in duplicates_map.items():
        # Determine verdict from the unique candidate
        unique_entry = original_entries[0]
        antipattern = unique_entry.get("antipattern", "")
        # Get number confirmed in unique analysis
        confirmed_count = confirmed_by_type.get(antipattern, {}).get('confirmed', 0)
        verdict = "YES" if confirmed_count > 0 else "NO"  # unique verdict
        # Assign verdict to all duplicates
        for _ in original_entries:
            if verdict == "YES":
                yes_mapped += 1
            elif verdict == "NO":
                no_mapped += 1
            else:
                error_mapped += 1

    with open(STATS_FILE, "w") as f:
        f.write("="*60 + "\n")
        f.write("LLM ANALYSIS STATISTICS\n")
        f.write("="*60 + "\n")
        f.write(f"Timestamp: {datetime.now()}\n\n")
        f.write(f"Total candidates loaded (pre-deduplication): {total_candidates}\n")
        f.write(f"Unique candidates analyzed (post-deduplication): {unique_candidates}\n")
        f.write(f"Duplicates removed: {total_candidates - unique_candidates}\n\n")

        f.write("ANALYSIS RESULTS (ALL ORIGINAL CANDIDATES)\n")
        f.write("-"*40 + "\n")
        f.write(f"Total analyzed: {total_mapped}\n")
        f.write(f"Confirmed (YES): {yes_mapped} ({yes_mapped/total_mapped*100:.1f}%)\n")
        f.write(f"Rejected (NO): {no_mapped} ({no_mapped/total_mapped*100:.1f}%)\n")
        f.write(f"Errors/Unknown: {error_mapped} ({error_mapped/total_mapped*100:.1f}%)\n\n")

        f.write("BREAKDOWN BY ANTIPATTERN\n")
        f.write("-"*40 + "\n")
        for antipattern, data in confirmed_by_type.items():
            # All original entries for this antipattern
            total_entries = sum(len(duplicates_map[key]) for key in duplicates_map if key[2] == normalize_string(antipattern))
            unique_confirmed = data['confirmed']
            # All duplicates inherit the unique verdict
            confirmed_entries = unique_confirmed * (total_entries // data['analyzed']) if data['analyzed'] > 0 else 0
            rejected_entries = total_entries - confirmed_entries
            percentage = (confirmed_entries / total_entries * 100) if total_entries > 0 else 0
            f.write(f"{antipattern}:\n")
            f.write(f"  Analyzed: {total_entries}\n")
            f.write(f"  Confirmed: {confirmed_entries} ({percentage:.1f}%)\n")
            f.write(f"  Rejected: {rejected_entries}\n\n")

        f.write("PERFORMANCE METRICS\n")
        f.write("-"*40 + "\n")
        f.write(f"Total time: {elapsed_time:.1f}s\n")
        f.write(f"Average per unique candidate: {elapsed_time/unique_candidates:.2f}s\n")
        f.write(f"Candidates per minute: {(total_candidates/elapsed_time)*60:.1f}\n")

# ================= MAIN =================

def main():
    print(f"Loading candidates from {INPUT_JSON}...")
    with open(INPUT_JSON) as f:
        candidates = json.load(f)

    total_candidates = len(candidates)
    print(f"Loaded {total_candidates} candidates")

    # Deduplicate
    unique_candidates, duplicates_map = deduplicate_candidates(candidates)
    unique_count = len(unique_candidates)
    print(f"{unique_count} unique candidates after deduplication")

    # Prepare CSV
    with open(OUTPUT_CSV, "w", newline="") as out:
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(["Assignment", "Class", "Method", "Antipattern", "Confirmed", "Explanation", "Evidence"])

        stats = {"total": 0, "yes": 0, "no": 0, "error": 0}
        confirmed_by_type = {}
        start_time = time.time()

        for i, unique_entry in enumerate(unique_candidates, 1):
            antipattern = unique_entry.get("antipattern", "")
            clazz = unique_entry.get("class", "")
            method = unique_entry.get("method", "")

            print(f"[{i}/{unique_count}] Analyzing: {clazz}.{method} ({antipattern})")
            stats["total"] += 1
            if antipattern not in confirmed_by_type:
                confirmed_by_type[antipattern] = {"analyzed": 0, "confirmed": 0}
            confirmed_by_type[antipattern]["analyzed"] += 1

            # LLM analysis
            result = analyze_candidate(unique_entry)
            verdict = result["verdict"]
            explanation = result["explanation"]

            if verdict == "YES":
                stats["yes"] += 1
                confirmed_by_type[antipattern]["confirmed"] += 1
                print(f"  ✓ CONFIRMED")
            elif verdict == "NO":
                stats["no"] += 1
                print(f"  ✗ REJECTED")
            else:
                stats["error"] += 1
                print(f"  ? {verdict}")

            # Write confirmed results for **all original entries**
            key = (
                normalize_string(clazz),
                normalize_string(method),
                normalize_string(antipattern),
                json.dumps(normalize_evidence(unique_entry.get("evidence", {})), sort_keys=True)
            )
            original_entries = duplicates_map[key]

            for original_entry in original_entries:
                assignment = original_entry.get("assignment") or original_entry.get("student")
                evidence_str = json.dumps(original_entry.get("evidence", {}), indent=2)
                if verdict == "YES":
                    writer.writerow([assignment, clazz, method, antipattern, "YES", explanation, evidence_str])

            time.sleep(0.2)

    elapsed_time = time.time() - start_time
    write_statistics(stats, confirmed_by_type, total_candidates, unique_count, duplicates_map, elapsed_time)


    print(f"\nAnalysis complete in {elapsed_time:.1f}s")
    print(f"Total analyzed: {stats['total']}")
    print(f"Confirmed (YES): {stats['yes']} ({stats['yes']/stats['total']*100:.1f}%)")
    print(f"Rejected (NO): {stats['no']} ({stats['no']/stats['total']*100:.1f}%)")
    print(f"Errors: {stats['error']}")
    print(f"Results written to {OUTPUT_CSV}")
    print(f"Statistics written to {STATS_FILE}")

if __name__ == "__main__":
    main()
