package com.nicole;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

public class MergeandPrepareLLMCandidates {

    public static void main(String[] args) throws Exception {
        List<String[]> originalCsv = readCsv("oop_antipattern_all.csv");
        List<String[]> astCsv = readCsv("oop_antipattern_ast_only.csv");

        Set<String> astConfirmedFingerprints = astCsv.stream()
                .map(row -> row[0] + "|" + row[1] + "|" + row[2] + "|" + row[3]) // Student|Class|Method|IssueType
                .collect(Collectors.toSet());

        List<Map<String,Object>> llmCandidates = new ArrayList<>();

        for (String[] row : originalCsv.subList(1, originalCsv.size())) {
    String fingerprint = row[0] + "|" + row[1] + "|" + row[2] + "|" + row[3];
    if (!astConfirmedFingerprints.contains(fingerprint)) {
        // Prepare candidate payload
        Map<String,Object> candidate = new HashMap<>();
        candidate.put("student", row[0]);
        candidate.put("class", row[1]);
        candidate.put("method", row[2]);
        candidate.put("antipattern", row[3]);
        String details = row.length > 5 ? row[5] : "";
        candidate.put("details", details);
        llmCandidates.add(candidate);
    }
}

        try (Writer w = new FileWriter("llm_candidates.json")) {
            w.write(new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(llmCandidates));
        }

        System.out.println("LLM candidates exported: " + llmCandidates.size());
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
        return line.split(",");
    }
}