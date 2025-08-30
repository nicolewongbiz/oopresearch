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
    class violates Liskov Substitution Principle (wrong abstraction).
    Returns a list of issues in format:
    [{ "class": "Cat", "method": "bark", "issue": "Wrong Abstraction" }, ...]
    """
    # Prompt to the LLM
    prompt = f"""
You are analyzing Java class structures for violations of the Liskov Substitution Principle.
Each class is given with its methods and parent classes.

Class data for student {student_name}:

{json.dumps(class_data, indent=2)}

Return a JSON array of objects with fields:
- class: name of the class that violates LSP
- method: method that should not exist or is wrongly inherited
- issue: always "Wrong Abstraction"

Example output:
[
  {{ "class": "Cat", "method": "bark", "issue": "Wrong Abstraction" }}
]
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
    writer = csv.writer(csvfile)

    for student_data in all_students:
        student_name = student_data.get("student", "Unknown")
        classes = student_data.get("classes", [])

        issues = check_lsp_violation(student_name, classes)

        for issue in issues:
            writer.writerow([
                student_name,
                student_name,               # Example folder same as student - change
                issue.get("class", ""),
                issue.get("method", ""),
                issue.get("issue", "Wrong Abstraction"),
                "Detected by LSP analysis"
            ])

print("LSP check complete, results appended to CSV.")
