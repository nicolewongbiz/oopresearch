package com.nicole;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class MergeandPrepareLLMCandidates {

    public static void main(String[] args) throws Exception {
        List<String[]> astCsv = readCsv("oop_antipattern_ast_only.csv");
        List<Map<String, Object>> detectorCandidates = loadDetectorCandidates("llm_candidates_detector.json");

        // Create a map of AST-confirmed issues for easy lookup
        Set<String> astConfirmedKeys = new HashSet<>();
        for (String[] row : astCsv) {
            if (row.length >= 4) {
                String student = clean(row[0]);
                String className = clean(row[1]);
                String methodName = clean(row[2]);
                String issueType = clean(row[3]);
                
                // Create a key for lookup
                String key = student + "|" + className + "|" + methodName + "|" + issueType;
                astConfirmedKeys.add(key);
            }
        }

        // Filter candidates
        List<Map<String, Object>> finalCandidates = new ArrayList<>();
        int filtered = 0;
        
        for (Map<String, Object> candidate : detectorCandidates) {
            String student = getString(candidate, "assignment");
            if (student == null) student = getString(candidate, "student");
            String className = getString(candidate, "class");
            String methodName = getString(candidate, "method");
            String antipattern = getString(candidate, "antipattern");
            
            if (student == null || className == null || methodName == null || antipattern == null) {
                continue;
            }
            
            // Clean and normalize
            student = clean(student);
            className = clean(className);
            methodName = clean(methodName);
            antipattern = clean(antipattern);
            
            // Map JSON antipattern to CSV format
            String csvIssueType = mapToCsvIssueType(antipattern);
            
            // Create the same key format
            String candidateKey = student + "|" + className + "|" + methodName + "|" + csvIssueType;
            
            if (astConfirmedKeys.contains(candidateKey)) {
                filtered++;
                System.out.println("FILTERED: " + candidateKey);
            } else {
                finalCandidates.add(candidate);
            }
        }

        // Write results
        try (Writer w = new FileWriter("llm_candidates.json")) {
            w.write(new GsonBuilder().setPrettyPrinting().create().toJson(finalCandidates));
        }

        System.out.println("\n=== RESULTS ===");
        System.out.println("Total candidates: " + detectorCandidates.size());
        System.out.println("AST-confirmed issues: " + astConfirmedKeys.size());
        System.out.println("Filtered out: " + filtered);
        System.out.println("Remaining for LLM: " + finalCandidates.size());
        System.out.println("Expected: " + (detectorCandidates.size() - filtered));
    // Add debug prints
System.out.println("\n=== DEBUG AST KEYS ===");
for (String key : astConfirmedKeys) {
    System.out.println("AST: " + key);
}

System.out.println("\n=== DEBUG CANDIDATE KEYS ===");
for (int i = 0; i < Math.min(10, detectorCandidates.size()); i++) {
    Map<String, Object> cand = detectorCandidates.get(i);
    String student = getString(cand, "assignment");
    if (student == null) student = getString(cand, "student");
    String className = getString(cand, "class");
    String methodName = getString(cand, "method");
    String antipattern = getString(cand, "antipattern");
    
    if (student != null && className != null && methodName != null && antipattern != null) {
        student = clean(student);
        className = clean(className);
        methodName = clean(methodName);
        antipattern = clean(antipattern);
        String csvIssueType = mapToCsvIssueType(antipattern);
        String key = student + "|" + className + "|" + methodName + "|" + csvIssueType;
        System.out.println("CAND " + i + ": " + key);
    }
}}
    
    private static String getString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }
    
    private static String clean(String text) {
        if (text == null) return "";
        return text.trim()
                  .replace("\"", "")
                  .replace("'", "")
                  .toLowerCase();
    }
    
    private static String mapToCsvIssueType(String jsonAntipattern) {
        // Simple mapping - adjust based on your actual data
        switch (jsonAntipattern) {
            case "redundantoverride":
                return "redundant override";
            case "switchcomplexity":
                return "switch complexity";
            case "typechecking":
            case "instanceofcheck":
            case "getclasscheck":
            case "typecheckingchain":
                return "type checking";
            case "defectiveemptyoverride":
            case "emptyoverrideinterface":
            case "emptyoverridewithcomments":
            case "ambiguousemptyoverride":
                return "improper polymorphism";
            case "potentialmissinginheritance":
                return "missing inheritance";
            default:
                return jsonAntipattern; // Return as-is if no mapping
        }
    }

    private static List<Map<String, Object>> loadDetectorCandidates(String filename) {
        try {
            Gson gson = new Gson();
            try (Reader reader = new FileReader(filename)) {
                return gson.fromJson(reader, 
                    new TypeToken<List<Map<String, Object>>>(){}.getType());
            }
        } catch (Exception e) {
            System.err.println("Error loading candidates: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private static List<String[]> readCsv(String path) throws IOException {
        List<String[]> rows = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (firstLine) {
                    firstLine = false; // Skip header
                    continue;
                }
                rows.add(parseCsvLine(line));
            }
        }
        return rows;
    }

    private static String[] parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            
            if (c == '"') {
                if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        
        fields.add(current.toString());
        return fields.toArray(new String[0]);
    }
}