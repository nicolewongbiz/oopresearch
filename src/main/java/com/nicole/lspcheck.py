#!/usr/bin/env python3

import json
import csv
import hashlib
from openai import OpenAI

INPUT_JSON = "llm_candidates.json"
OUTPUT_CSV = "oop_antipattern_lsp_only.csv"  # Changed output name
MODEL = "gpt-4o-mini"

client = OpenAI()

LSP_ANTIPATTERNS = {
    "PotentialLSPViolation",
    "EmptyOverride", 
    "RedundantOverride",
    "RedundantInheritance",
    "MissingInheritance"
}

LSP_SPECIFIC_PROMPTS = {
    "PotentialLSPViolation": """Analyze this method override for Liskov Substitution Principle violations.
Consider:
1. Does the subclass method strengthen preconditions?
2. Does it weaken postconditions (different return type, exceptions)?
3. Does it change the behavior in ways that would break code expecting the parent type?
4. Does it throw new exceptions not declared by parent?

Evidence: {evidence}

Answer YES if this violates LSP, NO if it's a valid override.""",
    
    "EmptyOverride": """An empty method override can violate LSP if the parent method has meaningful behavior.
Does this empty override break the contract established by the parent class?
Would substituting this subclass for its parent cause unexpected behavior?

Evidence: {evidence}

Answer YES if this violates LSP, NO if the empty override is acceptable.""",
    
    "RedundantOverride": """A redundant override that doesn't change behavior might indicate LSP issues.
Does this override violate the principle that subclasses should extend, not just repeat?
Could the parent method have been used directly?

Evidence: {evidence}

Answer YES if this indicates LSP violation, NO if it's acceptable.""",
    
    "RedundantInheritance": """Inheritance that doesn't add value might violate LSP.
Does this subclass truly extend the parent's behavior?
Would composition be more appropriate than inheritance here?

Evidence: {evidence}

Answer YES if this violates LSP principles, NO if inheritance is justified.""",
    
    "MissingInheritance": """Missing common abstraction might lead to LSP violations elsewhere.
Could extracting a common interface prevent future LSP violations?
Do these classes have substitutability issues?

Evidence: {evidence}

Answer YES if missing abstraction could cause LSP issues, NO if current design is fine."""
}

def create_fingerprint(entry):
    """Create a unique fingerprint for an entry."""
    evidence = entry.get("evidence", {})
    
    fingerprint_parts = [
        entry.get("assignment", ""),
        entry.get("class", ""),
        entry.get("method", ""),
        entry.get("antipattern", ""),
    ]
    
    if evidence:
        sorted_evidence = json.dumps(evidence, sort_keys=True)
        fingerprint_parts.append(sorted_evidence)
    
    fingerprint_str = "|".join(fingerprint_parts)
    return hashlib.md5(fingerprint_str.encode()).hexdigest()

def llm_analyze_lsp(antipattern, evidence):
    """Ask LLM if this is a genuine LSP violation."""
    if antipattern in LSP_SPECIFIC_PROMPTS:
        prompt = LSP_SPECIFIC_PROMPTS[antipattern].format(evidence=json.dumps(evidence, indent=2))
    else:
        # Generic LSP question for other patterns
        prompt = f"""Analyze this for Liskov Substitution Principle violations:
Antipattern: {antipattern}
Evidence: {json.dumps(evidence, indent=2)}

Does this represent an LSP violation or wrong abstraction?
Consider: substitutability, pre/post conditions, behavior changes.

Answer YES if this violates LSP, NO if it's acceptable design."""

    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=100
    )
    
    response = r.choices[0].message.content.strip().upper()
    return "YES" if "YES" in response else "NO"

def llm_explain_lsp_issue(antipattern, evidence):
    """Get explanation of LSP violation."""
    prompt = f"""Explain why this is a Liskov Substitution Principle violation.

Antipattern: {antipattern}
Evidence: {json.dumps(evidence, indent=2)}

Focus on:
1. How it violates substitutability
2. Which LSP condition is broken (pre/post/behavior)
3. Suggested refactoring to fix LSP

Keep explanation concise (2-3 sentences)."""
    
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=200
    )
    return r.choices[0].message.content.strip()

def format_csv_row(assignment_id, class_name, method_name, antipattern, explanation, evidence):
    """Format a row in the exact CSV format."""
    # Format evidence as JSON in code block
    evidence_json = json.dumps(evidence, indent=2)
    evidence_block = f"```json\n{evidence_json}\n```"
    
    # Escape and format with triple quotes
    assignment_id_escaped = f'"""{assignment_id}"""'
    class_name_escaped = f'"""{class_name}"""' if class_name else '""""""'
    method_name_escaped = f'"""{method_name}"""' if method_name else '""""""'
    antipattern_escaped = f'"""{antipattern}"""'
    explanation_escaped = f'"""{explanation}"""'
    evidence_escaped = f'"""{evidence_block}"""'
    
    return [
        assignment_id_escaped,
        class_name_escaped,
        method_name_escaped,
        antipattern_escaped,
        explanation_escaped,
        evidence_escaped
    ]

def deduplicate_candidates(candidates):
    seen = set()
    unique = []
    
    for entry in candidates:
        # Create key from everything except timestamp
        evidence = entry.get("evidence", {}).copy()
        if "timestamp" in evidence:
            del evidence["timestamp"]
        
        key = (
            entry.get("assignment", ""),
            entry.get("class", ""),
            entry.get("method", ""),
            entry.get("antipattern", ""),
            json.dumps(evidence, sort_keys=True)
        )
        
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    
    return unique



def main():
    with open(INPUT_JSON) as f:
        candidates = json.load(f)
    
    print(f"Loaded {len(candidates)} total candidates")
    
    # Filter for LSP-related antipatterns only
    lsp_candidates = [c for c in candidates if c.get("antipattern") in LSP_ANTIPATTERNS]
    print(f"Found {len(lsp_candidates)} LSP-related candidates")
    
    # Deduplicate candidates
    print("\nDeduplicating candidates...")
    unique_candidates = deduplicate_candidates(lsp_candidates)
    print(f"\nAfter deduplication: {len(unique_candidates)} unique LSP candidates")
    
    # Track stats
    stats = {pattern: {"total": 0, "yes": 0, "no": 0} for pattern in LSP_ANTIPATTERNS}
    
    with open(OUTPUT_CSV, "w", newline="") as out:
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(["Assignment", "Class", "Method", "Antipattern", "Explanation", "Evidence"])
        
        processed = 0
        for entry in unique_candidates:
            processed += 1
            assignment = entry.get("assignment", "")
            clazz = entry.get("class", "")
            method = entry.get("method", "")
            pattern = entry.get("antipattern", "")
            
            print(f"\n[{processed}/{len(unique_candidates)}] LSP check: {assignment}.{clazz}.{method} ({pattern})")
            
            # Track statistics
            stats[pattern]["total"] += 1
            
            verdict = llm_analyze_lsp(pattern, entry.get("evidence", {}))
            
            if verdict == "YES":
                stats[pattern]["yes"] += 1
                explanation = llm_explain_lsp_issue(pattern, entry.get("evidence", {}))
                
                
                row = format_csv_row(
                    assignment,
                    clazz,
                    method,
                    pattern,
                    explanation,
                    entry.get("evidence", {})
                )
                writer.writerow(row)
                print(f"  ✓ LSP VIOLATION CONFIRMED")
            else:
                stats[pattern]["no"] += 1
                print(f"  ✗ No LSP violation found")
    
    # Print LSP-specific statistics
    print(f"\n{'='*50}")
    print("LSP VIOLATION ANALYSIS RESULTS")
    print(f"{'='*50}")
    
    total_yes = sum(stats[p]["yes"] for p in LSP_ANTIPATTERNS)
    total_no = sum(stats[p]["no"] for p in LSP_ANTIPATTERNS)
    total_analyzed = total_yes + total_no

    if total_analyzed == 0:
        print("No LSP candidates found to analyze.")
        print(f"\nEmpty CSV created with header only at {OUTPUT_CSV}")
        return 
    
    
    for pattern in sorted(LSP_ANTIPATTERNS):
        pstats = stats[pattern]
        if pstats["total"] > 0:
            yes_pct = (pstats["yes"] / pstats["total"] * 100)
            print(f"{pattern}:")
            print(f"  Analyzed: {pstats['total']}")
            print(f"  LSP Violations: {pstats['yes']} ({yes_pct:.1f}%)")
            print(f"  OK: {pstats['no']}")
    
    print(f"\nSummary:")
    print(f"  Total LSP candidates analyzed: {total_analyzed}")
    print(f"  LSP violations found: {total_yes} ({total_yes/total_analyzed*100:.1f}%)")
    print(f"  OK designs: {total_no} ({total_no/total_analyzed*100:.1f}%)")
    
    print(f"\nLSP violation results written to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()