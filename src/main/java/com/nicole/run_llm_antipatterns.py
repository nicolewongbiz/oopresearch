#!/usr/bin/env python3

import json
import csv
import time
from openai import OpenAI

INPUT_JSON = "llm_candidates.json"
OUTPUT_CSV = "oop_antipattern_results.csv"
MODEL = "gpt-4o-mini"

client = OpenAI()

# Combined prompts - single LLM call for verdict AND explanation
ANTIPATTERN_PROMPTS = {
    "SwitchComplexity": """Analyze this switch statement evidence:
{evidence}

Guidelines for evaluation:
- Switches with 1-3 simple cases (like returning constants) → usually NO
- Switches with complex business logic in cases → likely YES
- Switches on enums for simple mapping (enum→value) → usually NO  
- Switches with 4+ cases containing if/loops/method calls → likely YES
- State machines or factory patterns may be acceptable

Question: Is this switch complexity problematic enough to warrant refactoring with polymorphism?

Answer: YES/NO: [brief explanation]""",
    
    "RedundantOverride": """Analyze this method override:
{evidence}

Guidelines:
- Override identical to parent with no changes → likely YES (redundant)
- Override that adds logging/validation → usually NO (has purpose)
- Empty override of non-abstract method → likely YES
- Override that calls super() with added logic → usually NO

Question: Is this override truly redundant with no purpose?

Answer: YES/NO: [brief explanation]""",
    
    "TypeChecking": """Analyze this type checking:
{evidence}

Guidelines:
- Checking type for simple dispatch (1-2 types) → usually NO
- Type checking with complex logic for each type → likely YES
- Type field that determines behavior in many methods → likely YES
- Simple configuration/setting checks → usually NO

Question: Should this type checking be replaced with polymorphism?

Answer: YES/NO: [brief explanation]""",
    
    "InstanceOfCheck": """Analyze this instanceof check:
{evidence}

Guidelines:
- instanceof for validation/null checks → usually NO
- instanceof for behavior dispatch (doing different things) → likely YES
- Single instanceof check → usually NO  
- Chain of instanceof checks in same method → likely YES

Question: Does this instanceof indicate missing polymorphism?

Answer: YES/NO: [brief explanation]""",
    
    "DefectiveEmptyOverride": """Analyze this empty override:
{evidence}

Guidelines:
- Empty override that disables parent's functionality → YES
- Empty override of trivial/no-op parent → maybe NO
- Empty override with comment explaining why → context needed
- Parent has important logic, child overrides with empty → YES

Question: Does this empty override violate Liskov Substitution Principle?

Answer: YES/NO: [brief explanation]""",
    
    # Default should be less strict
    "DEFAULT": """Analyze this potential antipattern:
{evidence}

Be conservative - only flag clear violations of OOP principles.
Consider:
1. Is this actually causing maintenance issues?
2. Would polymorphism clearly improve this?
3. Is this simple/clear enough as-is?

When in doubt, answer NO.

Question: Is this a legitimate antipattern that needs fixing?

Answer: YES/NO: [brief explanation]"""
}

def analyze_candidate(entry):
    """Single LLM call to analyze a candidate - returns verdict and explanation."""
    antipattern = entry.get("antipattern", "")
    evidence = entry.get("evidence", {})
    
    # Get the appropriate prompt
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
        
        # Parse the result
        if result.startswith("YES:"):
            verdict = "YES"
            explanation = result[4:].strip()
        elif result.startswith("NO:"):
            verdict = "NO"
            explanation = result[3:].strip()
        elif "YES:" in result:
            # Try to find YES: in the response
            parts = result.split("YES:", 1)
            if len(parts) > 1:
                verdict = "YES"
                explanation = parts[1].strip()
            else:
                verdict = "NO" if "NO" in result.upper() else "UNKNOWN"
                explanation = result
        elif "NO:" in result:
            parts = result.split("NO:", 1)
            if len(parts) > 1:
                verdict = "NO"
                explanation = parts[1].strip()
            else:
                verdict = "YES" if "YES" in result.upper() else "UNKNOWN"
                explanation = result
        else:
            # Fallback parsing
            upper_result = result.upper()
            if "YES" in upper_result and "NO" not in upper_result:
                verdict = "YES"
                explanation = result.replace("YES", "").replace("yes", "").strip(": ").strip()
            elif "NO" in upper_result:
                verdict = "NO"
                explanation = result.replace("NO", "").replace("no", "").strip(": ").strip()
            else:
                verdict = "UNKNOWN"
                explanation = result
        
        return {
            "verdict": verdict,
            "explanation": explanation,
            "raw_response": result
        }
        
    except Exception as e:
        print(f"Error analyzing candidate: {e}")
        return {
            "verdict": "ERROR",
            "explanation": f"Analysis failed: {str(e)}",
            "raw_response": ""
        }

def deduplicate_candidates(candidates):
    """Simple deduplication based on key fields."""
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

def main():
    print(f"Loading candidates from {INPUT_JSON}...")
    
    with open(INPUT_JSON) as f:
        candidates = json.load(f)
    
    print(f"Loaded {len(candidates)} candidates")
    
    # Deduplicate
    print("Deduplicating...")
    unique_candidates = deduplicate_candidates(candidates)
    print(f"After deduplication: {len(unique_candidates)} unique candidates")
    
    # Prepare CSV
    print(f"\nAnalyzing candidates with {MODEL}...")
    print("=" * 60)
    
    with open(OUTPUT_CSV, "w", newline="") as out:
        writer = csv.writer(out, quoting=csv.QUOTE_ALL)
        writer.writerow(["Assignment", "Class", "Method", "Antipattern", "Confirmed", "Explanation", "Evidence"])
        
        stats = {"total": 0, "yes": 0, "no": 0, "error": 0}
        start_time = time.time()
        
        for i, entry in enumerate(unique_candidates, 1):
            assignment = entry.get("assignment", "") or entry.get("student", "")
            clazz = entry.get("class", "")
            method = entry.get("method", "")
            antipattern = entry.get("antipattern", "")
            
            print(f"[{i}/{len(unique_candidates)}] Analyzing: {assignment}.{clazz}.{method} ({antipattern})")
            
            stats["total"] += 1
            
            # Single LLM call for analysis
            result = analyze_candidate(entry)
            verdict = result["verdict"]
            explanation = result["explanation"]
            
            # Update stats
            if verdict == "YES":
                stats["yes"] += 1
                print(f"  ✓ CONFIRMED")
            elif verdict == "NO":
                stats["no"] += 1
                print(f"  ✗ REJECTED")
            else:
                stats["error"] += 1
                print(f"  ? {verdict}")
            
            # Write to CSV if confirmed (YES)
            if verdict == "YES":
                # Format evidence as a string
                evidence_str = json.dumps(entry.get("evidence", {}), indent=2)
                
                writer.writerow([
                    assignment,
                    clazz,
                    method,
                    antipattern,
                    "YES",
                    explanation,
                    evidence_str
                ])
            
            # Small delay to avoid rate limits
            time.sleep(0.2)
    
    elapsed_time = time.time() - start_time
    
    # Print summary
    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Time taken: {elapsed_time:.1f} seconds")
    print(f"Average per candidate: {elapsed_time/len(unique_candidates):.1f} seconds")
    print(f"\nStatistics:")
    print(f"  Total analyzed: {stats['total']}")
    print(f"  Confirmed (YES): {stats['yes']} ({stats['yes']/stats['total']*100:.1f}%)")
    print(f"  Rejected (NO): {stats['no']} ({stats['no']/stats['total']*100:.1f}%)")
    print(f"  Errors: {stats['error']}")
    print(f"\nResults written to: {OUTPUT_CSV}")
    
    # Show breakdown by antipattern
    print(f"\nBreakdown by antipattern (confirmed only):")
    print("-" * 40)
    
    # Re-read CSV to count by antipattern
    try:
        with open(OUTPUT_CSV, "r") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
        
        print("(Check the CSV file for detailed results)")
    except:
        print("No confirmed issues found")

if __name__ == "__main__":
    main()