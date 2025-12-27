package com.nicole;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class MergeandPrepareLLMCandidates {

    public static void main(String[] args) throws Exception {
        // Load AST-only CSV
        List<String[]> astCsv = readCsv("oop_antipattern_ast_only.csv");
        // Load JSON candidates
        List<Map<String, Object>> detectorCandidates =
                loadDetectorCandidates("llm_candidates.json");

        // === BUILD AST-CONFIRMED KEYS ===
        // Each CSV row is ONE confirmed issue, even if it contains multiple methods
        Set<String> astConfirmedRowKeys = new HashSet<>();
        Set<String> astConfirmedKeys = new HashSet<>(); // For JSON subset matching
        
        System.out.println("=== Processing AST CSV rows ===");
        for (String[] row : astCsv) {
            if (row.length < 4) continue;

            String student = canonical(row[0]);
            String className = canonical(row[1]);
            String methodCell = canonical(row[2]);  // Keep as-is, even if it contains multiple methods
            String issueType = mapToCsvIssueType(canonical(row[3]));

            // Key includes the FULL method cell (could be single method or grouped)
            String key = student + "|" + className + "|" + methodCell + "|" + issueType;
            astConfirmedRowKeys.add(key);
            System.out.println("AST key added: " + key);
            
            // Also create individual method keys for subset matching
            String[] methods = methodCell.split(";");
            for (String method : methods) {
                method = method.trim();
                if (!method.isEmpty()) {
                    String individualKey = student + "|" + className + "|" + method + "|" + issueType;
                    astConfirmedKeys.add(individualKey);
                }
            }
        }

        System.out.println("\nAST-confirmed rows: " + astConfirmedRowKeys.size());
        System.out.println("AST-confirmed individual methods: " + astConfirmedKeys.size());
        
        // === CSV FILTERING (ALL - AST_ONLY) ===
        List<String[]> allCsv = readCsv("oop_antipattern_all.csv");
        List<String[]> filteredCsv = new ArrayList<>();

        System.out.println("\n=== Filtering CSV ===");
        for (String[] row : allCsv) {
            if (row.length < 4) continue;

            String student = canonical(row[0]);
            String className = canonical(row[1]);
            String methodCell = canonical(row[2]);  // Full method cell
            String issueType = mapToCsvIssueType(canonical(row[3]));

            String key = student + "|" + className + "|" + methodCell + "|" + issueType;
            
            if (astConfirmedRowKeys.contains(key)) {
                System.out.println("Filtering CSV row: " + key);
            } else {
                filteredCsv.add(row);
            }
        }

        writeCsv("oop_antipattern_filtered.csv", filteredCsv);

        // === FILTER JSON CANDIDATES ===
        List<Map<String, Object>> finalCandidates = new ArrayList<>();
        int filtered = 0;

        System.out.println("\n=== Filtering JSON Candidates ===");
        
        for (Map<String, Object> candidate : detectorCandidates) {
            String student = getString(candidate, "assignment");
            if (student == null || student.isEmpty()) {
                student = getString(candidate, "student");
            }

            String className = getString(candidate, "class");
            String methodName = getString(candidate, "method");
            String antipattern = getString(candidate, "antipattern");

            if (student == null || className == null || methodName == null || antipattern == null) {
                System.out.println("Skipping candidate with missing fields");
                finalCandidates.add(candidate); // Keep if we can't check
                continue;
            }

            student = canonical(student);
            className = canonical(className);
            String originalMethodName = methodName;
            methodName = canonical(methodName);  // Keep grouped methods as-is
            String issueType = mapJsonAntipatternToCsvIssue(antipattern);
            
            // Try to match with AST rows
            boolean shouldFilter = false;
            
            // First try: exact match (for grouped methods)
            String candidateKey = student + "|" + className + "|" + methodName + "|" + issueType;
            if (astConfirmedRowKeys.contains(candidateKey)) {
                shouldFilter = true;
                System.out.println("  Exact match filtered: " + candidateKey);
            } else {
                // Second try: check individual methods (JSON might have grouped methods too)
                String[] jsonMethods = methodName.split(";");
                for (String jsonMethod : jsonMethods) {
                    jsonMethod = jsonMethod.trim();
                    if (!jsonMethod.isEmpty()) {
                        String individualKey = student + "|" + className + "|" + jsonMethod + "|" + issueType;
                        if (astConfirmedKeys.contains(individualKey)) {
                            shouldFilter = true;
                            System.out.println("  Subset match filtered: " + individualKey);
                            break;
                        }
                    }
                }
            }

            if (shouldFilter) {
                filtered++;
                System.out.println("Filtered JSON candidate: " + student + "." + className + "." + originalMethodName + " [" + antipattern + "]");
            } else {
                finalCandidates.add(candidate);
            }
        }

        // Write filtered JSON
        try (Writer w = new FileWriter("llm_candidates.json")) {
            w.write(new GsonBuilder().setPrettyPrinting().create().toJson(finalCandidates));
        }

        System.out.println("\n=== FINAL RESULTS ===");
        System.out.println("AST-confirmed rows: " + astConfirmedRowKeys.size());
        System.out.println("AST-confirmed individual methods: " + astConfirmedKeys.size());
        System.out.println("Total CSV rows before filtering: " + allCsv.size());
        System.out.println("CSV rows after filtering: " + filteredCsv.size());
        System.out.println("JSON candidates before filtering: " + detectorCandidates.size());
        System.out.println("JSON candidates after filtering: " + finalCandidates.size());
        System.out.println("JSON filtered out: " + filtered);
        
        // Print debugging info
        if (filtered == 0 && finalCandidates.size() == detectorCandidates.size()) {
            System.out.println("\n=== DEBUG INFO ===");
            System.out.println("No JSON candidates were filtered!");
            System.out.println("\nSample of AST keys (first 5):");
            int count = 0;
            for (String key : astConfirmedKeys) {
                if (count++ >= 5) break;
                System.out.println("  " + key);
            }
            
            System.out.println("\nSample of JSON candidates (first 5):");
            count = 0;
            for (Map<String, Object> candidate : detectorCandidates) {
                if (count++ >= 5) break;
                String student = getString(candidate, "assignment");
                if (student == null) student = getString(candidate, "student");
                String className = getString(candidate, "class");
                String methodName = getString(candidate, "method");
                String antipattern = getString(candidate, "antipattern");
                
                student = canonical(student);
                className = canonical(className);
                methodName = canonical(methodName);
                String issueType = mapJsonAntipatternToCsvIssue(antipattern);
                
                System.out.println("  " + student + "|" + className + "|" + methodName + "|" + issueType);
            }
        }
    }

    // ================= HELPERS =================

    private static String getString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }

    private static String canonical(String text) {
        if (text == null) return "";
        return text.trim()
                .replace("\"", "")
                .replace("'", "")
                .replaceAll("\\s+", " ") // collapse multiple spaces
                .toLowerCase();
    }

    private static void writeCsv(String path, List<String[]> rows) throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(path))) {
            // Use original header format
            pw.println("\"Student\",\"Class\",\"Method\",\"IssueType\",\"Severity\",\"Details\"");
            for (String[] row : rows) {
                pw.println(
                        Arrays.stream(row)
                                .map(s -> "\"" + s.replace("\"", "\"\"") + "\"")
                                .collect(Collectors.joining(","))
                );
            }
        }
    }

    /**
     * Map CSV issue type (standardize variations)
     */
    private static String mapToCsvIssueType(String raw) {
        if (raw == null) return "";
        
        String lower = raw.toLowerCase();
        
        if (lower.contains("redundant override") || lower.contains("redundantoverride")) {
            return "redundant override";
        } else if (lower.contains("switch") && lower.contains("complexity")) {
            return "switch complexity";
        } else if (lower.contains("type check") || lower.contains("typecheck") || 
                   lower.contains("improper polymorphism")) {
            return "type checking";
        } else if (lower.contains("missing inheritance")) {
            return "missing inheritance";
        } else if (lower.contains("redundant inheritance")) {
            return "redundant inheritance";
        } else {
            return lower;
        }
    }

    /**
     * Map JSON antipattern type to CSV issue type
     */
    private static String mapJsonAntipatternToCsvIssue(String jsonAntipattern) {
        if (jsonAntipattern == null) return "";
        
        String lower = jsonAntipattern.toLowerCase();
        
        // Map JSON antipattern names to CSV issue types
        switch (lower) {
            case "redundantoverride":
            case "redundantoverridegroup":
                return "redundant override";
                
            case "switchcomplexity":
                return "switch complexity";
                
            case "typechecking":
            case "instanceofcheck":
            case "getclasscheck":
            case "defectiveemptyoverride":
            case "emptyoverrideinterface":
            case "emptyoverridewithcomments":
            case "ambiguousemptyoverride":
                return "type checking";
                
            case "potentialmissinginheritance":
            case "potentialmissinginheritancegroup":
                return "missing inheritance";
                
            case "redundantinheritance":
            case "redundantinheritancegroup":
                return "redundant inheritance";
                
            default:
                return mapToCsvIssueType(lower); // Fallback
        }
    }

    private static List<Map<String, Object>> loadDetectorCandidates(String filename) {
        try (Reader reader = new FileReader(filename)) {
            return new Gson().fromJson(
                    reader,
                    new TypeToken<List<Map<String, Object>>>() {}.getType()
            );
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
                    firstLine = false;
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