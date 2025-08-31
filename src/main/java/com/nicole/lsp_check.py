#!/usr/bin/env python3

import json
import csv
import os
from openai import OpenAI


# Configuration

JSON_FILE = "lsp_ast.json"          # JSON exported from LspAstExport.java
CSV_FILE = "oop_antipattern_results.csv" # Existing CSV from Java detector
OPENAI_MODEL = "gpt-4"                   # maybe use 5o

# set API key in environment:
# export OPENAI_API_KEY="your_api_key"
client = OpenAI()


def check_lsp_violation(student_name, class_data):
    """
    Sends the minimal class structure to the LLM and asks if any
    class violates the Liskov Substitution Principle (wrong abstraction).
    Returns a list of issues in format:
    [
      { "class": "Cat", "method": "bark", "issue": "Wrong Abstraction", "details": "Cat inherits bark() from Animal, which makes no semantic sense" }
    ]
    """
    # Prompt to the LLM
    prompt = f"""
You are analyzing Java class structures for violations of the Liskov Substitution Principle (LSP).


Class data for student {student_name}:

{json.dumps(class_data, indent=2)}

Return a JSON array of objects with fields:
- class: name of the class that violates LSP
- method: method that should not exist or is wrongly inherited
- issue: always "Wrong Abstraction"
- details: a short semantic reason why it makes no sense (e.g., "Cat inherits bark() from Animal, which makes no semantic sense").
"""

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    content = response.choices[0].message.content

    try:
        issues = json.loads(content)
        if not isinstance(issues, list):
            return []
        return issues
    except json.JSONDecodeError:
        print(f"Failed to parse LLM output for student {student_name}: {content}")
        return []


# Load JSON AST

with open(JSON_FILE, "r") as f:
    all_students = json.load(f)


# Append results to CSV

with open(CSV_FILE, "a", newline="") as csvfile:
    writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

    for student_data in all_students:
        student_name = student_data.get("student", "Unknown")
        classes = student_data.get("classes", [])

        issues = check_lsp_violation(student_name, classes)

        for issue in issues:
            details = issue.get("details")
            if not details:
                details = f"{issue.get('class', '')} inherits {issue.get('method', '')} inappropriately (wrong abstraction)."
            writer.writerow([
                student_name,
                issue.get("class", ""),
                issue.get("method", ""),
                issue.get("issue", "Wrong Abstraction"),
                details
            ])

print("LSP check complete, results appended to CSV.")
