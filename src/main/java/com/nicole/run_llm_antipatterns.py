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

Guidelines for evaluation:
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

    # Default fallback
    "DEFAULT": """Analyze this potential antipattern:
{evidence}

Be conservative; only flag clear OOP violations.
When in doubt, answer NO.

Question: Is this a legitimate antipattern that needs fixing?

Answer: YES/NO: [brief explanation]"""
}

# ================= FUNCTIONS =================

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
            # Fallback parsing
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
    """Remove exact duplicate candidates."""
    seen = set()
    unique = []

    for entry in candidates:
        key = (
            entry.get("assignment", "") or entry.get("student", ""),
            entry.get("class", ""),
            entry.get("method", ""),
            entry.get("antipattern", ""),
            json.dumps(entry.get("evidence", {}), sort_keys=True)
        )
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    return unique


def write_statistics(stats, confirmed_by_type, total_candidates, unique_candidates, elapsed_time):
    """Write stats file per-antipattern without grouping."""
    with open(STATS_FILE, "w") as f:
        f.write("="*60 + "\n")
        f.write("LLM ANALYSIS STATISTICS\n")
        f.write("="*60 + "\n")
        f.write(f"Timestamp: {datetime.now()}\n\n")
        f.write(f"Total candidates loaded: {total_candidates}\n")
        f.write(f"After deduplication: {unique_candidates}\n")
        f.write(f"Duplicates removed: {total_candidates - unique_candidates}\n\n")

        f.write("ANALYSIS RESULTS\n")
        f.write("-"*40 + "\n")
        f.write(f"Total analyzed: {stats['total']}\n")
        f.write(f"Confirmed (YES): {stats['yes']} ({stats['yes']/stats['total']*100:.1f}%)\n")
        f.write(f"Rejected (NO): {stats['no']} ({stats['no']/stats['total']*100:.1f}%)\n")
        f.write(f"Errors/Unknown: {stats['error']} ({stats['error']/stats['total']*100:.1f}%)\n\n")

        f.write("BREAKDOWN BY ANTIPATTERN\n")
        f.write("-"*40 + "\n")
        for antipattern, data in confirmed_by_type.items():
            analyzed = data['analyzed']
            confirmed = data['confirmed']
            percentage = (confirmed / analyzed * 100) if analyzed > 0 else 0
            f.write(f"{antipattern}:\n")
            f.write(f"  Analyzed: {analyzed}\n")
            f.write(f"  Confirmed: {confirmed} ({percentage:.1f}%)\n")
            f.write(f"  Rejected: {analyzed - confirmed}\n\n")

        f.write("PERFORMANCE METRICS\n")
        f.write("-"*40 + "\n")
        f.write(f"Total time: {elapsed_time:.1f}s\n")
        f.write(f"Average per candidate: {elapsed_time/unique_candidates:.2f}s\n")
        f.write(f"Candidates per minute: {(unique_candidates/elapsed_time)*60:.1f}\n")


# ================= MAIN =================

def main():
    print(f"Loading candidates from {INPUT_JSON}...")
    with open(INPUT_JSON) as f:
        candidates = json.load(f)

    total_candidates = len(candidates)
    print(f"Loaded {total_candidates} candidates")

    # Deduplicate
    unique_candidates = deduplicate_candidates(candidates)
    unique_count = len(unique_candidates)
    print(f"{unique_count} unique candidates after deduplication")

    # Prepare CSV
    with open(OUTPUT_CSV, "w", newline="") as out:
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(["Assignment", "Class", "Method", "Antipattern", "Confirmed", "Explanation", "Evidence"])

        stats = {"total": 0, "yes": 0, "no": 0, "error": 0}
        confirmed_by_type = {}
        start_time = time.time()

        for i, entry in enumerate(unique_candidates, 1):
            assignment = entry.get("assignment", "") or entry.get("student", "")
            clazz = entry.get("class", "")
            method = entry.get("method", "")
            antipattern = entry.get("antipattern", "")

            print(f"[{i}/{unique_count}] Analyzing: {assignment}.{clazz}.{method} ({antipattern})")

            stats["total"] += 1
            if antipattern not in confirmed_by_type:
                confirmed_by_type[antipattern] = {"analyzed": 0, "confirmed": 0}
            confirmed_by_type[antipattern]["analyzed"] += 1

            result = analyze_candidate(entry)
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

            # Write confirmed results only
            if verdict == "YES":
                evidence_str = json.dumps(entry.get("evidence", {}), indent=2)
                writer.writerow([assignment, clazz, method, antipattern, "YES", explanation, evidence_str])

            time.sleep(0.2)  # optional rate-limit delay

    elapsed_time = time.time() - start_time
    write_statistics(stats, confirmed_by_type, total_candidates, unique_count, elapsed_time)

    # Print summary
    print(f"\nAnalysis complete in {elapsed_time:.1f}s")
    print(f"Total analyzed: {stats['total']}")
    print(f"Confirmed (YES): {stats['yes']} ({stats['yes']/stats['total']*100:.1f}%)")
    print(f"Rejected (NO): {stats['no']} ({stats['no']/stats['total']*100:.1f}%)")
    print(f"Errors: {stats['error']}")
    print(f"Results written to {OUTPUT_CSV}")
    print(f"Statistics written to {STATS_FILE}")

if __name__ == "__main__":
    main()
