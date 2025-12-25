package com.nicole;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class MergeandPrepareLLMCandidates {

    public static void main(String[] args) throws Exception {
        List<String[]> originalCsv = readCsv("oop_antipattern_all.csv");
        List<String[]> astCsv = readCsv("oop_antipattern_ast_only.csv");
        
        // Load the LLM candidates that your detector already created with rich context
        List<Map<String, Object>> detectorCandidates = loadDetectorCandidates("llm_candidates_detector.json");

        Set<String> astConfirmedFingerprints = astCsv.stream()
                .map(row -> row[0] + "|" + row[1] + "|" + row[2] + "|" + row[3]) // Student|Class|Method|IssueType
                .collect(Collectors.toSet());

        // Filter: Keep only detector candidates that are NOT in astConfirmedFingerprints
        List<Map<String, Object>> finalCandidates = new ArrayList<>();
        
        for (Map<String, Object> candidate : detectorCandidates) {
            String student = (String) candidate.get("student");
            String className = (String) candidate.get("class");
            String methodName = (String) candidate.get("method");
            String antipattern = (String) candidate.get("antipattern");
            
            String fingerprint = student + "|" + className + "|" + methodName + "|" + antipattern;
            
            if (!astConfirmedFingerprints.contains(fingerprint)) {
                // This candidate needs LLM review (not confirmed by AST)
                finalCandidates.add(candidate);
            }
        }

        try (Writer w = new FileWriter("llm_candidates.json")) {
            w.write(new GsonBuilder().setPrettyPrinting().create().toJson(finalCandidates));
        }

        System.out.println("LLM candidates for review: " + finalCandidates.size());
        System.out.println("Total detector candidates: " + detectorCandidates.size());
        System.out.println("AST-confirmed issues: " + astConfirmedFingerprints.size());
    }

    private static List<Map<String, Object>> loadDetectorCandidates(String filename) {
        try {
            Gson gson = new Gson();
            try (Reader reader = new FileReader(filename)) {
                return gson.fromJson(reader, 
                    new TypeToken<List<Map<String, Object>>>(){}.getType());
            }
        } catch (Exception e) {
            System.err.println("Could not load detector candidates: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private static List<String[]> readCsv(String path) throws IOException {
        List<String[]> rows = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                rows.add(parseCsvLine(line));
            }
        }
        return rows;
    }

    private static String[] parseCsvLine(String line) {
        // Handle CSV with quotes
        List<String> fields = new ArrayList<>();
        StringBuilder currentField = new StringBuilder();
        boolean inQuotes = false;
        
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                fields.add(currentField.toString().replace("\"\"", "\""));
                currentField = new StringBuilder();
            } else {
                currentField.append(c);
            }
        }
        
        // Add last field
        fields.add(currentField.toString().replace("\"\"", "\""));
        
        return fields.toArray(new String[0]);
    }
}