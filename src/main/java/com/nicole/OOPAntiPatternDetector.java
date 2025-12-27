package com.nicole;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.comments.Comment;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.utils.SourceRoot;


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class OOPAntiPatternDetector {

    private static final Gson GSON = new GsonBuilder()
        .setPrettyPrinting()  // Makes JSON readable
        .create();

    // Add these static counters at the top of your class
private static int totalStudentsAnalyzed = 0;
private static int totalJavaFilesProcessed = 0;
private static int totalClassesAnalyzed = 0;
private static int totalMethodsScanned = 0;
private static int totalStatementsAnalyzed = 0;

    private static List<String[]> csvRows = new ArrayList<>();
    private static final Set<String> FRAMEWORK_METHOD_NAMES = Set.of("setUp", "tearDown");
    private static final Set<String> OBJECT_METHOD_NAMES = Set.of("equals", "hashCode", "toString");
    
    // NEW: List for LLM candidates
    private static List<Map<String, Object>> llmCandidates = new ArrayList<>();

    private static void addCsvRow(String studentName, String className, 
                         String methodName, String issueType, 
                         String severity, String details) {
    if (shouldSkipClassName(className)) {
        return;
    }
    
    // Create a unique key for this detection
    String uniqueKey = studentName + "|" + className + "|" + methodName;
    
    // If we already have an issue for this method, check if we should keep it
    for (int i = 0; i < csvRows.size(); i++) {
        String[] existingRow = csvRows.get(i);
        if (existingRow[0].equals(studentName) && 
            existingRow[1].equals(className) && 
            existingRow[2].equals(methodName)) {
            
            // Keep the HIGHER severity issue
            if (getSeverityLevel(severity) > getSeverityLevel(existingRow[4])) {
                csvRows.set(i, new String[]{studentName, className, methodName, 
                                           issueType, severity, details});
            }
            return; // Don't add duplicate
        }
    }
    
    // No existing issue for this method, add it
    csvRows.add(new String[]{
        studentName,
        className,
        methodName,
        issueType,
        severity,
        details
    });
}



private static int getSeverityLevel(String severity) {
    switch (severity) {
        case "HIGH": return 3;
        case "MEDIUM": return 2;
        case "LOW": return 1;
        default: return 0;
    }
}

private static boolean shouldSkipClassName(String className) {
    return className.equals("Main") || 
           className.endsWith("Test") ||
           className.contains("Test") ||
           className.equals("MessageCli") ||
           className.equals("Types");
}

private static void detectLSPViolations(ClassOrInterfaceDeclaration childClass,
                                       ClassOrInterfaceDeclaration parentClass,
                                       String assignmentId) {
    
    Map<String, MethodDeclaration> parentMethods = getMethodSignatures(parentClass);
    Map<String, MethodDeclaration> childMethods = getMethodSignatures(childClass);
    
    for (Map.Entry<String, MethodDeclaration> entry : childMethods.entrySet()) {
        String signature = entry.getKey();
        MethodDeclaration childMethod = entry.getValue();
        MethodDeclaration parentMethod = parentMethods.get(signature);
        
        if (parentMethod == null) continue;
        
        if (parentMethod.isAbstract()) {
            continue;
        }
        
        Optional<BlockStmt> childBody = childMethod.getBody();
        if (childBody.isEmpty()) {
            continue;
        }

        boolean childIsEmpty = isEmptyBody(childBody.get());
        if (!childIsEmpty) {
            continue;
        }
        
        Optional<BlockStmt> parentBody = parentMethod.getBody();
        if (parentBody.isEmpty()) {
            String details = "Empty override of interface/default method";
            addCsvRow(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "EmptyOverrideInterface",
                "MEDIUM", details);
            
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "EmptyOverrideInterface",
                Map.of(
                    "details", details,
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentType", "interface/default",
                    "astVerdict", "NEEDS_LLM_REVIEW"
                ));
            continue;
        }
        
        // Check if parent body is also empty
        boolean parentIsEmpty = isEmptyBody(parentBody.get());
        if (parentIsEmpty) {
            // Both empty - usually fine, but check for comments
            String parentBodyStr = parentBody.get().toString();
            boolean parentHasComments = hasMeaningfulComments(parentBodyStr);
            
            if (parentHasComments) {
                // Parent has comments suggesting expected behavior
                String details = "Empty override of documented empty method";
                addCsvRow(assignmentId, childClass.getNameAsString(),
                    childMethod.getNameAsString(), "EmptyOverrideWithComments",
                    "LOW", details);
                    
                
                addLLMCandidate(assignmentId, childClass.getNameAsString(),
                    childMethod.getNameAsString(), "EmptyOverrideWithComments",
                    Map.of(
                        "details", details,
                        "parentSignature", parentMethod.getDeclarationAsString(),
                        "childSignature", childMethod.getDeclarationAsString(),
                        "parentBody", parentBodyStr,
                        "parentHasComments", "true",
                        "astVerdict", "NEEDS_LLM_REVIEW"
                    ));
            }
            // If no comments, skip - both truly empty is fine
            continue;
        }
        
        // Parent has non-empty body, child overrides with empty
        String parentBodyStr = parentBody.get().toString();
        boolean parentHasRealLogic = hasRealLogic(parentBody.get());
        
        if (parentHasRealLogic) {
            // Clear violation: parent has logic, child disables it
            String details = "Empty override disables parent's logic";
            addCsvRow(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "DefectiveEmptyOverride",
                "HIGH", details);
            
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "DefectiveEmptyOverride",
                Map.of(
                    "details", details,
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentBodyPreview", getBodyPreview(parentBodyStr),
                    "parentLogicComplexity", assessComplexity(parentBody.get()),
                    "astVerdict", "CLEAR_VIOLATION"
                ));
        } else {
            // Parent body exists but is trivial
            String details = "Empty override of trivial parent method";
            addCsvRow(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "AmbiguousEmptyOverride",
                "MEDIUM", details);
            
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "AmbiguousEmptyOverride",
                Map.of(
                    "details", details,
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentBody", parentBodyStr,
                    "parentIsTrivial", "true",
                    "astVerdict", "NEEDS_LLM_REVIEW"
                ));
        }
    }
}


    public static void main(String[] args) throws Exception {
    // Hardcoded submissions directory
    File submissionsDir = new File("C:\\Users\\GGPC\\Downloads\\assignment-2022-3\\assignment-3_output");
    
    if (!submissionsDir.exists()) {
        System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
        return;
    }

    System.out.println("Analyzing folder: " + submissionsDir.getAbsolutePath());

    // CSV header
    csvRows.add(new String[]{"Student", "Class", "Method", "IssueType", "Severity", "Details"});

    // Iterate all java files inside student folders (include nested)
    List<File> javaFiles = new ArrayList<>();
    Map<String, String> fileToStudent = new HashMap<>();

    File[] studentDirs = submissionsDir.listFiles();
    if (studentDirs != null) {
        for (File studentDir : studentDirs) {
            if (!studentDir.isDirectory()) continue;
            totalStudentsAnalyzed++;  // Count student
            
            String studentName = studentDir.getName();
            Path studentPath;
            try {
                studentPath = studentDir.toPath().toRealPath();
            } catch (IOException e) {
                System.err.println("Could not canonicalise student dir " + studentDir + ": " + e.getMessage());
                continue;
            }

            try (Stream<Path> walk = Files.walk(studentPath)) {
                walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".java"))
                    .forEach(p -> {
                        File f = p.toFile();
                        javaFiles.add(f);
                        totalJavaFilesProcessed++;  // Count Java file
                        fileToStudent.put(f.getAbsolutePath(), studentName);
                    });
            } catch (IOException e) {
                System.err.println("Failed walking " + studentDir + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    System.out.println("\n=== STATISTICS COLLECTED ===");
    System.out.println("Total students analyzed: " + totalStudentsAnalyzed);
    System.out.println("Total Java files processed: " + totalJavaFilesProcessed);

    // Parse all files
    List<CompilationUnit> units = new ArrayList<>();
    JavaParser parser = new JavaParser();
    for (File f : javaFiles) {
        ParseResult<CompilationUnit> result = parser.parse(f);
        if (result.isSuccessful() && result.getResult().isPresent()) {
            CompilationUnit cu = result.getResult().get();
            cu.setStorage(f.toPath());
            units.add(cu);
        } else {
            System.err.println("Could not parse: " + f.getAbsolutePath());
            result.getProblems().forEach(System.err::println);
        }
    }

    // Group classes by student
    Map<String, Map<String, ClassOrInterfaceDeclaration>> groupedClassMaps = new HashMap<>();
    List<CompilationUnit> validUnits = new ArrayList<>();

    for (CompilationUnit cu : units) {
        if (!cu.getStorage().isPresent()) continue;
        String keyPath = cu.getStorage().get().getPath().toAbsolutePath().toString();
        String studentName = fileToStudent.get(keyPath);
        if (studentName == null) continue;

        groupedClassMaps.computeIfAbsent(studentName, k -> new HashMap<>());

        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            // FILTER HERE - BEFORE adding to map!
            String className = clazz.getNameAsString();
            
            // Skip Main and other framework classes
            if (className.equals("Main") || 
                className.equals("MessageCli") || 
                className.equals("Types") ||
                className.endsWith("Test") ||
                className.contains("Test")) {
                System.out.println("Skipping framework class: " + className + " for " + studentName);
                continue;
            }
            
            groupedClassMaps.get(studentName).put(className, clazz);
            totalClassesAnalyzed++;  // Count class
            
            // Count methods in this class
            int methodCount = clazz.getMethods().size();
            totalMethodsScanned += methodCount;
            
            // Count statements in all methods
            for (MethodDeclaration method : clazz.getMethods()) {
                if (method.getBody().isPresent()) {
                    totalStatementsAnalyzed += method.getBody().get().getStatements().size();
                }
            }
        }
        validUnits.add(cu);
    }

    System.out.println("Total classes analyzed (excluding framework): " + totalClassesAnalyzed);
    System.out.println("Total methods scanned: " + totalMethodsScanned);
    System.out.println("Total statements analyzed: " + totalStatementsAnalyzed);
    System.out.println("Average methods per class: " + 
        (totalClassesAnalyzed > 0 ? String.format("%.2f", (double)totalMethodsScanned / totalClassesAnalyzed) : "0"));
    System.out.println("Average statements per method: " + 
        (totalMethodsScanned > 0 ? String.format("%.2f", (double)totalStatementsAnalyzed / totalMethodsScanned) : "0"));
    System.out.println("================================\n");

        Set<String> allEnumNames = collectAllEnumNames(validUnits);

        System.out.println("\nParsed classes (grouped by student):");
// Perform detections per student
for (Map.Entry<String, Map<String, ClassOrInterfaceDeclaration>> entry : groupedClassMaps.entrySet()) {
    String studentName = entry.getKey();
    String assignmentId = extractAssignmentId(studentName);
    Map<String, ClassOrInterfaceDeclaration> classMap = entry.getValue();

    System.out.println("\n=== Running detections for " + studentName + " (Assignment: " + assignmentId + ") ===");

    // DEBUG: Show what classes we have
    System.out.println("Classes for " + studentName + ": " + String.join(", ", classMap.keySet()));

    // ========== PER-CLASS DETECTIONS ==========
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        String className = clazz.getNameAsString();
        
        // CRITICAL FIX: Skip framework classes EARLY
        if (shouldSkipClass(clazz)) {
            System.out.println("Skipping class: " + className);
            continue;
        }
        
        System.out.println("Analyzing class: " + className);
        
        analyzeEnumUsage(clazz, studentName);

        if (hasTypeField(clazz)) {
            detectTypeCheckingInMethods(clazz, studentName);
        }
    }

    // ========== INHERITANCE-BASED DETECTIONS ==========
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (shouldSkipClass(clazz)) {
            continue;
        }
        
        if (!clazz.getExtendedTypes().isEmpty()) {
            String parentName = clazz.getExtendedTypes(0).getNameAsString();
            ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
            
            if (parentClass != null) {
                detectRedundantOverrides(clazz, parentClass, studentName, classMap);
                detectLSPViolations(clazz, parentClass, assignmentId);
            }
        }
    }

    detectMissingInheritance(classMap, studentName);
    detectRedundantSuperclass(classMap, studentName);
}

        String outputFile = "oop_antipattern_all.csv";
        writeCsv(outputFile);

        writeDetectorCandidates("llm_candidates.json");
        writeLLMCandidates("llm_candidates.json");
        writeStatisticsToFile();
        // Also print to console
System.out.println("\n=== FINAL STATISTICS ===");
System.out.println("Total students analyzed: " + totalStudentsAnalyzed);
System.out.println("Total Java files processed: " + totalJavaFilesProcessed);
System.out.println("Total classes analyzed (excluding framework): " + totalClassesAnalyzed);
System.out.println("Total methods scanned: " + totalMethodsScanned);
System.out.println("Total heuristic issues detected: " + (csvRows.size() - 1)); // -1 for header
System.out.println("Total LLM candidates generated: " + llmCandidates.size());
        
        System.out.println("\nAnalysis complete! Results saved to: " + outputFile);
        System.out.println("LLM candidates saved to: llm_candidates.json");
    }

    private static String extractAssignmentId(String studentName) {
    if (studentName.contains("assignment")) {
        return studentName;
    }
    
    // Try to find patterns
    String[] parts = studentName.split("[-_]");
    if (parts.length >= 2) {
        try {
            Integer.parseInt(parts[0]);
            return studentName;
        } catch (NumberFormatException e) {
            if (parts.length >= 3) {
                return "assignment-" + parts[parts.length-2] + "-" + parts[parts.length-1];
            }
        }
    }
    
    return studentName;
}

private static void writeStatisticsToFile() {
    try (PrintWriter pw = new PrintWriter(new File("detection_statistics.txt"))) {
        pw.println("=== OOP ANTIPATTERN DETECTION STATISTICS ===");
        pw.println("Timestamp: " + new java.util.Date());
        pw.println();
        pw.println("Input Data:");
        pw.println("  Total students analyzed: " + totalStudentsAnalyzed);
        pw.println("  Total Java files processed: " + totalJavaFilesProcessed);
        pw.println("  Total classes analyzed (excluding framework): " + totalClassesAnalyzed);
        pw.println("  Total methods scanned: " + totalMethodsScanned);
        pw.println("  Total statements analyzed: " + totalStatementsAnalyzed);
        pw.println();
        pw.println("Averages:");
        pw.println("  Average methods per class: " + 
            (totalClassesAnalyzed > 0 ? String.format("%.2f", (double)totalMethodsScanned / totalClassesAnalyzed) : "0"));
        pw.println("  Average statements per method: " + 
            (totalMethodsScanned > 0 ? String.format("%.2f", (double)totalStatementsAnalyzed / totalMethodsScanned) : "0"));
        pw.println();
        pw.println("Detection Results:");
        pw.println("  Total AST-obvious issues: " + 54); // You'll update this
        pw.println("  Total heuristic issues detected: " + csvRows.size());
        pw.println("  Total LLM candidates generated: " + llmCandidates.size());
        
        // Count by issue type
        // In writeStatisticsToFile() method:
Map<String, Integer> issueTypeCounts = new HashMap<>();
for (int i = 1; i < csvRows.size(); i++) {  // Skip header
    String[] row = csvRows.get(i);
    if (row.length > 3) {
        String issueType = row[3];
        
        // COMBINE "Redundant Inheritance Group" with "Redundant Inheritance"
        if (issueType.equals("Redundant Inheritance Group")) {
            issueType = "Redundant Inheritance";
        }
        
        // COMBINE "RedundantOverrideGroup" with "Redundant Override" 
        if (issueType.equals("RedundantOverrideGroup")) {
            issueType = "Redundant Override";
        }
        
        // COMBINE "PotentialMissingInheritanceGroup" with "Missing Inheritance"
        if (issueType.equals("PotentialMissingInheritanceGroup")) {
            issueType = "Missing Inheritance";
        }
        
        issueTypeCounts.put(issueType, issueTypeCounts.getOrDefault(issueType, 0) + 1);
    }
}
        
        pw.println();
        pw.println("Issue Type Breakdown:");
        for (Map.Entry<String, Integer> entry : issueTypeCounts.entrySet()) {
            pw.println("  " + entry.getKey() + ": " + entry.getValue());
        }
        
    } catch (Exception e) {
        System.err.println("Failed to write statistics: " + e.getMessage());
    }
}


private static boolean shouldSkipClass(ClassOrInterfaceDeclaration clazz) {
    String className = clazz.getNameAsString();
    
    // Skip framework/boilerplate classes
    if (className.equals("Main") || 
        className.equals("MessageCli") ||
        className.equals("Types") ||
        className.equals("OperatorManagementSystem") || // If this is provided framework
        className.endsWith("Test") ||
        className.contains("Test") ||
        className.startsWith("Test") ||
        className.contains("CliTest")) {
        return true;
    }
    
    // Skip classes with only static methods (likely utilities)
    boolean allMethodsStatic = true;
    for (MethodDeclaration method : clazz.getMethods()) {
        if (!method.isStatic()) {
            allMethodsStatic = false;
            break;
        }
    }
    if (allMethodsStatic && clazz.getMethods().size() > 0) {
        return true; // Skip utility classes
    }
    
    // Skip empty classes
    if (clazz.getMethods().isEmpty() && clazz.getFields().isEmpty()) {
        return true;
    }
    
    // Skip inner classes (they're part of another class's design)
    Optional<Node> parent = clazz.getParentNode();
    if (parent.isPresent() && parent.get() instanceof ClassOrInterfaceDeclaration) {
        return true; // Skip inner classes
    }
    
    return false;
}

private static void writeDetectorCandidates(String filename) {
    try (FileWriter writer = new FileWriter(filename)) {
        GSON.toJson(llmCandidates, writer);
        System.out.println("Detector LLM candidates written to " + filename);
    } catch (Exception e) {
        System.err.println("Failed to write detector candidates: " + e.getMessage());
        e.printStackTrace();
    }
}
 
private static boolean hasRealLogic(BlockStmt body) {
    String normalized = body.toString()
        .replaceAll("//.*|/\\*(.|\\R)*?\\*/", "")
        .replaceAll("\\s+", "")
        .replaceAll("[{};]", "");

    return !normalized.isEmpty() && 
           !normalized.equals("return") &&
           !normalized.equals("returnnull") &&
           !normalized.equals("return0") &&
           !normalized.equals("returnfalse") &&
           !normalized.equals("returntrue") &&
           !normalized.startsWith("returnthis") &&
           normalized.length() > 10;
}

private static boolean hasMeaningfulComments(String body) {
    return body.contains("TODO") || 
           body.contains("FIXME") ||
           body.contains("IMPLEMENT") ||
           body.contains("override") ||
           body.contains("Override") ||
           (body.contains("/*") && body.indexOf("*/") - body.indexOf("/*") > 10);
}

private static String getBodyPreview(String body) {
    if (body.length() <= 100) return body;
    return body.substring(0, 100) + "...";
}

private static String assessComplexity(BlockStmt body) {
    int statementCount = body.getStatements().size();
    String bodyStr = body.toString();
    
    if (statementCount == 1 && bodyStr.contains("return")) {
        return "SIMPLE_RETURN";
    } else if (statementCount <= 3) {
        return "LOW";
    } else if (statementCount <= 10) {
        return "MEDIUM";
    } else {
        return "HIGH";
    }
}
    
    // =============== HELPER METHODS FOR LSP DETECTION ===============
    
    private static Map<String, MethodDeclaration> getMethodSignatures(ClassOrInterfaceDeclaration clazz) {
        Map<String, MethodDeclaration> methods = new HashMap<>();
        for (MethodDeclaration method : clazz.getMethods()) {
            methods.put(method.getSignature().asString(), method);
        }
        return methods;
    }
    
    private static boolean isEmptyBody(BlockStmt body) {
        return body.getStatements().isEmpty() || 
               body.toString().trim().equals("{}");
    }
    
    private static String formatExceptions(List<com.github.javaparser.ast.type.ReferenceType> exceptions) {
        return exceptions.stream()
            .map(e -> e.toString())
            .collect(Collectors.joining(", "));
    }
    
    private static void addLLMCandidate(String assignmentId, String className, 
                                   String methodName, String issueType,
                                   Map<String, Object> evidence) {

        if (shouldSkipClassName(className)) {
        return;
    }
    Map<String, Object> candidate = new HashMap<>();
    candidate.put("assignment", assignmentId);  // <-- KEY: "assignment" not "student"
    candidate.put("class", className);
    candidate.put("method", methodName);
    candidate.put("antipattern", issueType);
    candidate.put("evidence", evidence);
    candidate.put("timestamp", System.currentTimeMillis());
    llmCandidates.add(candidate);
} 
    
    private static void writeLLMCandidates(String filename) {
    try (FileWriter writer = new FileWriter(filename)) {
        GSON.toJson(llmCandidates, writer);
        System.out.println("LLM candidates written to " + filename);
    } catch (Exception e) {
        System.err.println("Failed to write LLM candidates: " + e.getMessage());
        e.printStackTrace();
    }
}
    
    private static String mapToJson(Map<String, Object> map) {
        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            entries.add(String.format("\"%s\": \"%s\"", 
                entry.getKey(), 
                entry.getValue().toString().replace("\"", "\\\"")));
        }
        return "{" + String.join(", ", entries) + "}";
    }

    // =============== EXISTING METHODS (unchanged) ===============
    
    private static void writeCsv(String fileName) {
        try (PrintWriter pw = new PrintWriter(new File(fileName))) {
            for (String[] row : csvRows) {
                StringJoiner sj = new StringJoiner(",");
                for (String field : row) {
                    if (field == null) field = "";
                    String escaped = "\"" + field.replace("\"", "\"\"") + "\"";
                    sj.add(escaped);
                }
                pw.println(sj.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean hasTypeField(ClassOrInterfaceDeclaration clazz) {
        return clazz.getFields().stream()
                .flatMap(f -> f.getVariables().stream())
                .anyMatch(v -> v.getNameAsString().equals("type"));
    }

    private static Set<String> collectAllEnumNames(List<CompilationUnit> units) {
        Set<String> enumNames = new HashSet<>();
        for (CompilationUnit cu : units) {
            cu.findAll(EnumDeclaration.class)
              .forEach(enumDecl -> enumNames.add(enumDecl.getNameAsString()));
        }
        return enumNames;
    }

    private static void detectTypeCheckingInMethods(ClassOrInterfaceDeclaration clazz, 
                                               String studentName) {
    for (MethodDeclaration method : clazz.getMethods()) {
        Optional<BlockStmt> body = method.getBody();
        if (body.isEmpty()) continue;

        BlockStmt methodBody = body.get();
        
        for (Statement stmt : methodBody.getStatements()) {
            if (stmt.isIfStmt()) {
                IfStmt ifStmt = stmt.asIfStmt();
                Expression cond = ifStmt.getCondition();

                if (isTypeEqualsCheck(cond)) {
                    // Output to CSV (simple format)
                    String details = "type.equals(...) check";
                    addCsvRow(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "Improper Polymorphism",
                        "HIGH", details);
                    
                    // Output to LLM candidates with richer context
                    addLLMCandidate(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "TypeChecking",
                        Map.of(
                            "details", details,
                            "checkType", "type.equals",
                            "condition", cond.toString(),
                            "methodComplexity", assessMethodComplexity(method)
                        ));
                }
                
                if (cond instanceof InstanceOfExpr) {
                    // Output to CSV (simple format)
                    String details = "Uses instanceof instead of polymorphism";
                    addCsvRow(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "Type Checking",
                        "MEDIUM", details);
                    
                    // Output to LLM candidates with richer context
                    InstanceOfExpr instanceOf = (InstanceOfExpr) cond;
                    addLLMCandidate(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "InstanceOfCheck",
                        Map.of(
                            "details", details,
                            "checkType", "instanceof",
                            "checkedType", instanceOf.getType().toString(),
                            "checkedExpression", instanceOf.getExpression().toString(),
                            "methodComplexity", assessMethodComplexity(method)
                        ));
                }
            }
        }
        
        methodBody.findAll(BinaryExpr.class).forEach(binaryExpr -> {
            if (binaryExpr.getOperator() == BinaryExpr.Operator.EQUALS ||
                binaryExpr.getOperator() == BinaryExpr.Operator.NOT_EQUALS) {
                
                String expr = binaryExpr.toString();
                if (expr.contains(".getClass()") || expr.contains(".class")) {
                    // Output to CSV (simple format)
                    String details = "Uses getClass() or .class comparison instead of polymorphism";
                    addCsvRow(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "Type Checking",
                        "MEDIUM", details);
                    
                    // Output to LLM candidates with richer context
                    addLLMCandidate(studentName, clazz.getNameAsString(),
                        method.getNameAsString(), "GetClassCheck",
                        Map.of(
                            "details", details,
                            "checkType", "getClass/.class",
                            "expression", expr,
                            "methodComplexity", assessMethodComplexity(method)
                        ));
                }
            }
        });
    }
}



    private static boolean isTypeEqualsCheck(Expression expr) {
        if (!(expr instanceof MethodCallExpr)) return false;
        MethodCallExpr mcall = (MethodCallExpr) expr;

        if (!mcall.getNameAsString().equals("equals")) return false;
        if (mcall.getScope().isEmpty()) return false;

        Expression scope = mcall.getScope().get();
        return scope instanceof NameExpr && ((NameExpr) scope).getNameAsString().equals("type");
    }

    private static void analyzeEnumUsage(ClassOrInterfaceDeclaration clazz, 
                                    String studentName) {
    // CRITICAL: Check if this is a Main class or should be skipped
    if (shouldSkipClass(clazz)) {
        return; // Exit immediately
    }
    
    for (MethodDeclaration method : clazz.getMethods()) {
        Optional<BlockStmt> body = method.getBody();
        if (body.isEmpty()) continue;
        
        // Find ALL switches in this method
        List<SwitchStmt> switches = body.get().findAll(SwitchStmt.class);
        if (switches.isEmpty()) {
            continue; // No switches in this method - SKIP ENTIRELY
        }
        
        // Analyze ALL switches in this method
        List<SwitchAnalysis> switchAnalyses = new ArrayList<>();
        int totalSwitches = switches.size();
        int totalCases = 0;
        double totalComplexity = 0;
        boolean hasComplexLogic = false;
        boolean hasObjectCreation = false;
        String highestSeverity = "LOW";
        
        for (SwitchStmt switchStmt : switches) {
            SwitchAnalysis analysis = analyzeSwitchComplexity(switchStmt);
            
            // Skip trivial switches (3 or fewer cases, no complex logic)
            if (analysis.caseCount <= 3 && !analysis.hasComplexLogic) {
                System.out.println("Skipping trivial switch: " + analysis.caseCount + " cases");
                totalSwitches--;  // Decrement count for trivial switches
                continue; // Skip to next switch
            }
            
            switchAnalyses.add(analysis);
            
            totalCases += analysis.caseCount;
            totalComplexity += analysis.complexityScore;
            if (analysis.hasComplexLogic) hasComplexLogic = true;
            if (analysis.hasObjectCreation) hasObjectCreation = true;
            
            // Determine severity for this individual switch
            String switchSeverity = getSwitchSeverity(switchStmt);
            if (switchSeverity.equals("HIGH")) {
                highestSeverity = "HIGH";
            } else if (switchSeverity.equals("MEDIUM") && !highestSeverity.equals("HIGH")) {
                highestSeverity = "MEDIUM";
            } else if (highestSeverity.equals("LOW")) {
                // Keep it LOW if no higher severity found
            }
        }
        
        // Check if we have ANY valid switches left
        if (totalSwitches == 0 || switchAnalyses.isEmpty()) {
            continue; // Skip this method entirely
        }
        
        // Calculate averages
        double avgCases = totalSwitches > 0 ? (double) totalCases / totalSwitches : 0;
        double avgComplexity = totalSwitches > 0 ? totalComplexity / totalSwitches : 0;
        
        // Determine overall pattern based on ALL switches in this method
        String overallPattern = determineOverallPattern(switchAnalyses);
        
        // Only output ONCE per method with ALL switches aggregated
        String details = String.format(
            "Method contains %d switch(es) with %d total cases, avg %.1f cases/switch, pattern: %s",
            totalSwitches, totalCases, avgCases, overallPattern
        );
        
        addCsvRow(studentName, clazz.getNameAsString(),
            method.getNameAsString(), // Method name
            "Switch Complexity",
            highestSeverity, // Use the highest severity among switches
            details);
        
        // Create switch breakdown with more details
        List<Map<String, Object>> switchBreakdown = new ArrayList<>();
        for (SwitchAnalysis analysis : switchAnalyses) {
            Map<String, Object> switchInfo = new HashMap<>();
            switchInfo.put("patternType", analysis.patternType);
            switchInfo.put("contentPattern", analysis.contentPattern);
            switchInfo.put("caseCount", analysis.caseCount);
            switchInfo.put("complexityScore", analysis.complexityScore);
            switchInfo.put("hasComplexLogic", analysis.hasComplexLogic);
            switchInfo.put("hasObjectCreation", analysis.hasObjectCreation);
            
            // Add what the switch actually does
            switchInfo.put("isStringMapping", analysis.contentPattern.equals("STRING_MAPPING"));
            switchInfo.put("isSimpleMapping", analysis.contentPattern.equals("SIMPLE_MAPPING") || 
                                               analysis.contentPattern.equals("STRING_MAPPING"));
            switchBreakdown.add(switchInfo);
        }

        // Update evidence map
        Map<String, Object> evidence = new HashMap<>();
        evidence.put("totalSwitches", String.valueOf(totalSwitches));
        evidence.put("totalCases", String.valueOf(totalCases));
        evidence.put("avgCasesPerSwitch", String.format("%.1f", avgCases));
        evidence.put("avgComplexityScore", String.format("%.1f", avgComplexity));
        evidence.put("overallPattern", overallPattern);
        evidence.put("contentPattern", getDominantContentPattern(switchAnalyses));
        evidence.put("hasComplexLogic", String.valueOf(hasComplexLogic));
        evidence.put("hasObjectCreation", String.valueOf(hasObjectCreation));
        evidence.put("highestSeverity", highestSeverity);
        evidence.put("methodSignature", method.getDeclarationAsString());
        evidence.put("switchBreakdown", switchBreakdown);
        evidence.put("suggestion", getSuggestionForSwitches(totalSwitches, avgCases, overallPattern));
        evidence.put("isConfigurationSwitch", isConfigurationSwitch(switchAnalyses));
        evidence.put("methodName", method.getNameAsString());
        evidence.put("className", clazz.getNameAsString());
        evidence.put("isEventHandler", method.getNameAsString().toLowerCase().contains("click") || 
                                       method.getNameAsString().toLowerCase().contains("mouse") || 
                                       method.getNameAsString().toLowerCase().contains("key"));
        evidence.put("isGetterSetter", method.getNameAsString().startsWith("get") || 
                                        method.getNameAsString().startsWith("set") ||
                                        method.getNameAsString().startsWith("is"));

        addLLMCandidate(studentName, clazz.getNameAsString(),
            method.getNameAsString(), "SwitchComplexity", evidence);
    }
}

private static String getDominantContentPattern(List<SwitchAnalysis> analyses) {
    if (analyses.isEmpty()) return "UNKNOWN";
    
    Map<String, Integer> patternCounts = new HashMap<>();
    for (SwitchAnalysis analysis : analyses) {
        patternCounts.put(analysis.contentPattern, 
            patternCounts.getOrDefault(analysis.contentPattern, 0) + 1);
    }
    
    return patternCounts.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse("MIXED");
}

private static boolean isConfigurationSwitch(List<SwitchAnalysis> analyses) {
    for (SwitchAnalysis analysis : analyses) {
        if (analysis.contentPattern.equals("STRING_MAPPING") || 
            analysis.contentPattern.equals("SIMPLE_MAPPING")) {
            return true;
        }
    }
    return false;
}

private static String determineOverallPattern(List<SwitchAnalysis> analyses) {
    if (analyses.isEmpty()) {
        return "NO_VALID_SWITCHES";
    }
    
    // Count pattern types
    Map<String, Integer> patternCounts = new HashMap<>();
    for (SwitchAnalysis analysis : analyses) {
        patternCounts.put(analysis.patternType, 
            patternCounts.getOrDefault(analysis.patternType, 0) + 1);
    }
    
    // Return the most common pattern
    return patternCounts.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .map(Map.Entry::getKey)
        .orElse("MIXED");
}

private static String getSuggestionForSwitches(int totalSwitches, double avgCases, String pattern) {
    if (pattern.equals("NO_VALID_SWITCHES")) {
        return "No complex switches found"; // Or return null/empty
    }
    
    if (totalSwitches > 3) {
        return "Consider refactoring - too many switches in one method";
    }
    if (avgCases > 5) {
        return "Switch has many cases - consider polymorphism";
    }
    if (pattern.equals("STATE_MACHINE")) {
        return "State machine pattern detected - consider State pattern";
    }
    if (pattern.equals("FACTORY_PATTERN")) {
        return "Factory pattern - acceptable but could use Factory Method pattern";
    }
    return "Review for potential polymorphism replacement";
}

    private static String getSwitchSeverity(SwitchStmt switchStmt) {
    // Get full analysis (already includes content pattern)
    SwitchAnalysis analysis = analyzeSwitchComplexity(switchStmt);
    
    // ========== NEW LOGIC FIRST ==========
    // Content-based severity overrides
    if (analysis.contentPattern.equals("STRING_MAPPING") || 
        analysis.contentPattern.equals("SIMPLE_MAPPING")) {
        return "LOW"; // Simple mapping switches are fine
    } else if (analysis.contentPattern.equals("METHOD_DISPATCH")) {
        // Method dispatch could be problematic
        if (analysis.hasObjectCreation && analysis.caseCount > 3) {
            return "MEDIUM"; // Factory with many cases
        } else {
            return "LOW"; // Simple method dispatch
        }
    } else if (analysis.contentPattern.equals("COMPLEX_LOGIC")) {
        return "HIGH"; // Complex logic is always high
    } else if (analysis.contentPattern.equals("STATE_CHANGE")) {
        return "MEDIUM"; // State changes are medium
    }
    
    // ========== ORIGINAL LOGIC (for other patterns) ==========
    if (analysis.caseCount == 0) return "LOW";
    double avgLines = analysis.avgLinesPerCase;

    if (analysis.hasComplexLogic || avgLines >= 5.0) {
        return "HIGH";
    } else if (analysis.hasObjectCreation && avgLines >= 3.0) {
        return "MEDIUM";
    } else if (analysis.hasObjectCreation && avgLines <= 2.0) {
        return "LOW";
    } else {
        // Default for remaining cases
        return "MEDIUM";
    }
}
private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, 
                                        ClassOrInterfaceDeclaration parent, 
                                        String studentName,
                                        Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    // List to collect redundant methods in this class
    List<String> redundantMethods = new ArrayList<>();
    Map<String, MethodDeclaration> parentMethods = new HashMap<>();
    Map<String, MethodDeclaration> childMethodMap = new HashMap<>();
    Map<String, Map<String, Object>> llmEvidenceMap = new HashMap<>();
    
    for (MethodDeclaration pm : parent.getMethods()) {
        parentMethods.put(pm.getSignature().asString(), pm);
    }

    for (MethodDeclaration childMethod : child.getMethods()) {
        childMethodMap.put(childMethod.getSignature().asString(), childMethod);
        
        String sig = childMethod.getSignature().asString();
        if (!parentMethods.containsKey(sig)) continue;

        MethodDeclaration parentMethod = parentMethods.get(sig);

        if (parentMethod.getBody().isPresent() && childMethod.getBody().isPresent()) {
            BlockStmt parentBody = parentMethod.getBody().get();
            BlockStmt childBody = childMethod.getBody().get();

            removeAllComments(parentBody);
            removeAllComments(childBody);

            String parentBodyStr = parentBody.toString().trim().replaceAll("\\s+", " ");
            String childBodyStr = childBody.toString().trim().replaceAll("\\s+", " ");

            if (parentBodyStr.equals(childBodyStr)) {
                if (!isJustifiedIdenticalOverride(childMethod, child, parent, classMap)) {
                    redundantMethods.add(childMethod.getNameAsString());
                    
                    // Store LLM evidence for this method
                    llmEvidenceMap.put(childMethod.getNameAsString(), Map.of(
                        "parentSignature", parentMethod.getDeclarationAsString(),
                        "childSignature", childMethod.getDeclarationAsString(),
                        "bodySimilarity", "100",
                        "parentIsAbstract", String.valueOf(parentMethod.isAbstract()),
                        "methodComplexity", assessMethodComplexity(parentMethod),
                        "isGetterSetter", String.valueOf(isGetterOrSetter(childMethod)),
                        "isConstructor", String.valueOf(checkIfConstructor(childMethod))
                    ));
                }
            }
        }
    }
    
    // Group all redundant methods in this class together
    if (!redundantMethods.isEmpty()) {
        if (redundantMethods.size() == 1) {
            // Single method - handle normally
            String methodName = redundantMethods.get(0);
            String details = "Identical to parent method";
            addCsvRow(studentName, child.getNameAsString(),
                methodName, "Redundant Override",
                "MEDIUM", details);
            
            addLLMCandidate(studentName, child.getNameAsString(),
                methodName, "RedundantOverride",
                llmEvidenceMap.get(methodName));
        } else {
            // Multiple methods - group them
            String methodsStr = String.join("; ", redundantMethods);
            String details = redundantMethods.size() + " methods identical to parent: " + methodsStr;
            
            // Add grouped CSV row
            addCsvRow(studentName, child.getNameAsString(),
                methodsStr, "Redundant Override",
                "MEDIUM", details);
            
            // Add a single LLM candidate for the group with combined evidence
            Map<String, Object> groupEvidence = new HashMap<>();
            groupEvidence.put("redundantMethodsCount", String.valueOf(redundantMethods.size()));
            groupEvidence.put("redundantMethods", String.join(", ", redundantMethods));
            groupEvidence.put("details", "Multiple methods with identical implementations to parent");
            groupEvidence.put("methodExamples", getMethodExamples(redundantMethods, childMethodMap));
            
            addLLMCandidate(studentName, child.getNameAsString(),
                methodsStr, "RedundantOverrideGroup",
                groupEvidence);
        }
    }
}

// Helper method to get method examples for the group
private static String getMethodExamples(List<String> methodNames, Map<String, MethodDeclaration> childMethodMap) {
    List<String> examples = new ArrayList<>();
    for (String methodName : methodNames) {
        // Find the method by name (simplified - in reality you'd need to match signatures)
        for (Map.Entry<String, MethodDeclaration> entry : childMethodMap.entrySet()) {
            if (entry.getValue().getNameAsString().equals(methodName)) {
                examples.add(entry.getValue().getDeclarationAsString());
                break;
            }
        }
        if (examples.size() >= 3) break; // Limit to 3 examples
    }
    return String.join("; ", examples);
}


    // =============== METHOD COMPLEXITY ASSESSMENT ===============

private static String assessMethodComplexity(MethodDeclaration method) {
    if (method.getBody().isEmpty()) {
        return "ABSTRACT_OR_INTERFACE";
    }
    
    BlockStmt body = method.getBody().get();
    List<Statement> statements = body.getStatements();
    
    // Basic metrics
    int statementCount = statements.size();
    int lineCount = countNonEmptyLines(body.toString());
    
    // Control flow complexity
    int ifCount = body.findAll(IfStmt.class).size();
    int loopCount = body.findAll(ForStmt.class).size() + 
                    body.findAll(WhileStmt.class).size() +
                    body.findAll(DoStmt.class).size() +
                    body.findAll(com.github.javaparser.ast.stmt.ForEachStmt.class).size();
    int switchCount = body.findAll(SwitchStmt.class).size();
    
    // Method calls complexity
    int methodCallCount = body.findAll(MethodCallExpr.class).size();
    int externalCallCount = countExternalCalls(method);
    
    // Exception handling
    int tryCatchCount = body.findAll(TryStmt.class).size();
    
    // Depth complexity (simplified)
    int maxNestingDepth = calculateMaxNestingDepth(body);
    
    // Return type complexity
    String returnTypeComplexity = assessReturnTypeComplexity(method.getType());
    
    // Parameter complexity
    int paramCount = method.getParameters().size();
    String paramComplexity = assessParameterComplexity(method.getParameters());
    
    // Calculate overall complexity score
    int complexityScore = calculateComplexityScore(
        statementCount, ifCount, loopCount, switchCount,
        methodCallCount, externalCallCount, tryCatchCount,
        maxNestingDepth, paramCount
    );
    
    // Build complexity profile
    Map<String, Object> profile = new HashMap<>();
    profile.put("statementCount", statementCount);
    profile.put("lineCount", lineCount);
    profile.put("controlFlowElements", ifCount + loopCount + switchCount);
    profile.put("methodCalls", methodCallCount);
    profile.put("externalCalls", externalCallCount);
    profile.put("exceptionHandlers", tryCatchCount);
    profile.put("maxNestingDepth", maxNestingDepth);
    profile.put("returnTypeComplexity", returnTypeComplexity);
    profile.put("parameterComplexity", paramComplexity);
    profile.put("complexityScore", complexityScore);
    
    // Determine complexity level
    String complexityLevel;
    if (complexityScore >= 30) {
        complexityLevel = "HIGH";
    } else if (complexityScore >= 15) {
        complexityLevel = "MEDIUM";
    } else if (complexityScore >= 5) {
        complexityLevel = "LOW";
    } else {
        complexityLevel = "VERY_LOW";
    }
    
    profile.put("complexityLevel", complexityLevel);
    
    // Additional heuristics for antipattern detection
    profile.put("isGetterSetter", isGetterOrSetter(method));
    profile.put("isConstructor", checkIfConstructor(method));
    profile.put("isOverride", method.getAnnotationByName("Override").isPresent());
    profile.put("hasSideEffects", hasSideEffects(body));
    profile.put("isPureFunction", isPureFunction(method, body));
    
    // Convert to JSON string for easy parsing
    return mapToJson(profile);
}

private static boolean checkIfConstructor(MethodDeclaration method) {
    // Check if the method has the same name as its parent class
    Optional<Node> parent = method.getParentNode();
    if (parent.isPresent() && parent.get() instanceof ClassOrInterfaceDeclaration) {
        ClassOrInterfaceDeclaration clazz = (ClassOrInterfaceDeclaration) parent.get();
        return method.getNameAsString().equals(clazz.getNameAsString());
    }
    return false;
}

private static int countNonEmptyLines(String code) {
    return (int) code.lines()
        .filter(line -> !line.trim().isEmpty() && !line.trim().startsWith("//"))
        .count();
}

private static int countExternalCalls(MethodDeclaration method) {
    BlockStmt body = method.getBody().orElse(null);
    if (body == null) return 0;
    
    Set<String> localMethods = new HashSet<>();
    Node parentClass = method.getParentNode().orElse(null);
    if (parentClass instanceof ClassOrInterfaceDeclaration) {
        ClassOrInterfaceDeclaration clazz = (ClassOrInterfaceDeclaration) parentClass;
        clazz.getMethods().forEach(m -> localMethods.add(m.getNameAsString()));
        // Also get constructor names
        clazz.getConstructors().forEach(c -> localMethods.add(c.getNameAsString()));
    }
    
    int externalCalls = 0;
    for (MethodCallExpr call : body.findAll(MethodCallExpr.class)) {
        if (call.getScope().isPresent()) {
            Expression scope = call.getScope().get();
            // Check if it's calling methods on other objects (not this)
            if (!scope.toString().equals("this") && 
                !scope.toString().equals("super") &&
                !(scope instanceof NameExpr && 
                  ((NameExpr) scope).getNameAsString().equals(method.getNameAsString()))) {
                externalCalls++;
            }
        } else if (!call.getNameAsString().equals(method.getNameAsString()) &&
                  !localMethods.contains(call.getNameAsString())) {
            // Static or local calls that aren't to this class's methods
            externalCalls++;
        }
    }
    
    return externalCalls;
}

private static int calculateMaxNestingDepth(Node node) {
    int maxDepth = 0;
    List<Node> children = node.getChildNodes();
    
    for (Node child : children) {
        if (isControlFlowNode(child)) {
            int childDepth = 1 + calculateMaxNestingDepth(child);
            if (childDepth > maxDepth) {
                maxDepth = childDepth;
            }
        } else {
            int childDepth = calculateMaxNestingDepth(child);
            if (childDepth > maxDepth) {
                maxDepth = childDepth;
            }
        }
    }
    
    return maxDepth;
}

private static boolean isControlFlowNode(Node node) {
    return node instanceof IfStmt ||
           node instanceof ForStmt ||
           node instanceof WhileStmt ||
           node instanceof DoStmt ||
           node instanceof SwitchStmt ||
           node instanceof TryStmt ||
           node instanceof CatchClause ||
           node instanceof SynchronizedStmt;
}

private static String assessReturnTypeComplexity(com.github.javaparser.ast.type.Type type) {
    String typeStr = type.toString();
    
    if (typeStr.equals("void")) return "VOID";
    if (typeStr.equals("boolean") || typeStr.equals("int") || 
        typeStr.equals("long") || typeStr.equals("double") || 
        typeStr.equals("float") || typeStr.equals("char") || 
        typeStr.equals("byte") || typeStr.equals("short")) {
        return "PRIMITIVE";
    }
    if (typeStr.equals("String")) return "STRING";
    if (typeStr.startsWith("List<") || typeStr.startsWith("Set<") || 
        typeStr.startsWith("Map<") || typeStr.startsWith("Collection<")) {
        return "COLLECTION";
    }
    if (typeStr.contains("[]")) return "ARRAY";
    if (typeStr.startsWith("Optional<")) return "OPTIONAL";
    
    // Check for complex generic types
    if (typeStr.contains("<") && typeStr.contains(">")) {
        return "COMPLEX_GENERIC";
    }
    
    return "OBJECT";
}

private static String assessParameterComplexity(List<Parameter> parameters) {
    if (parameters.isEmpty()) return "NO_PARAMS";
    
    int primitiveCount = 0;
    int objectCount = 0;
    int collectionCount = 0;
    int optionalCount = 0;
    
    for (Parameter param : parameters) {
        String typeStr = param.getType().toString();
        if (typeStr.equals("boolean") || typeStr.equals("int") || 
            typeStr.equals("long") || typeStr.equals("double") || 
            typeStr.equals("float") || typeStr.equals("char") || 
            typeStr.equals("byte") || typeStr.equals("short")) {
            primitiveCount++;
        } else if (typeStr.startsWith("List<") || typeStr.startsWith("Set<") || 
                  typeStr.startsWith("Map<") || typeStr.startsWith("Collection<")) {
            collectionCount++;
        } else if (typeStr.startsWith("Optional<")) {
            optionalCount++;
        } else {
            objectCount++;
        }
    }
    
    if (parameters.size() > 5) return "MANY_PARAMS";
    if (collectionCount > 0) return "HAS_COLLECTIONS";
    if (optionalCount > 0) return "HAS_OPTIONALS";
    if (objectCount > primitiveCount) return "MOSTLY_OBJECTS";
    
    return "MOSTLY_PRIMITIVES";
}

private static int calculateComplexityScore(int... metrics) {
    int score = 0;
    
    // Statement count weight
    score += Math.min(metrics[0] * 2, 20); // Max 20 points
    
    // Control flow weight
    score += (metrics[1] + metrics[2] + metrics[3]) * 3; // if/loops/switches
    
    // Method calls weight
    score += Math.min(metrics[4] * 1, 10); // Internal calls
    score += Math.min(metrics[5] * 2, 20); // External calls
    
    // Exception handling weight
    score += metrics[6] * 4; // try-catch blocks
    
    // Nesting depth weight
    score += metrics[7] * 5; // Nesting depth
    
    // Parameter count weight
    score += Math.min(metrics[8], 5) * 2; // Parameters
    
    return score;
}

private static boolean isGetterOrSetter(MethodDeclaration method) {
    String name = method.getNameAsString();
    
    if (method.getParameters().isEmpty()) {
        // Potential getter
        if (name.startsWith("get") && name.length() > 3 && 
            Character.isUpperCase(name.charAt(3))) {
            return true;
        }
        if (name.startsWith("is") && name.length() > 2 && 
            Character.isUpperCase(name.charAt(2)) &&
            method.getType().toString().equals("boolean")) {
            return true;
        }
    } else if (method.getParameters().size() == 1 && 
               method.getType().toString().equals("void")) {
        // Potential setter
        if (name.startsWith("set") && name.length() > 3 && 
            Character.isUpperCase(name.charAt(3))) {
            return true;
        }
    }
    
    return false;
}

private static boolean hasSideEffects(BlockStmt body) {
    // Check for assignments to fields, static variables, or method calls that might have side effects
    List<AssignExpr> assignments = body.findAll(AssignExpr.class);
    for (AssignExpr assign : assignments) {
        String target = assign.getTarget().toString();
        if (target.contains("this.") || 
            target.contains(".") && !target.startsWith("local")) {
            return true;
        }
    }
    
    // Check for method calls that typically have side effects
    for (MethodCallExpr call : body.findAll(MethodCallExpr.class)) {
        String name = call.getNameAsString().toLowerCase();
        if (name.contains("add") || name.contains("remove") || 
            name.contains("put") || name.contains("set") ||
            name.contains("write") || name.contains("print") ||
            name.contains("save") || name.contains("update") ||
            name.contains("delete") || name.contains("create")) {
            return true;
        }
    }
    
    return false;
}

private static boolean isPureFunction(MethodDeclaration method, BlockStmt body) {
    // A pure function: no side effects, deterministic output based only on inputs
    if (hasSideEffects(body)) return false;
    
    // Check if it modifies any fields
    ClassOrInterfaceDeclaration parentClass = method.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
    if (parentClass != null) {
        Set<String> fieldNames = getAllFieldNames(parentClass);
        String bodyStr = body.toString();
        for (String field : fieldNames) {
            // Check for field modifications (excluding "this.field" in assignments)
            if (bodyStr.contains(field + " =") || 
                bodyStr.contains(field + "+=") ||
                bodyStr.contains(field + "-=") ||
                bodyStr.contains(field + "++") ||
                bodyStr.contains("++" + field) ||
                bodyStr.contains(field + "--") ||
                bodyStr.contains("--" + field)) {
                return false;
            }
        }
    }
    
    // Check for non-deterministic calls
    for (MethodCallExpr call : body.findAll(MethodCallExpr.class)) {
        String name = call.getNameAsString().toLowerCase();
        if (name.contains("random") || name.contains("currenttimemillis") || 
            name.contains("nanotime") || name.contains("system.") ||
            name.contains("math.random")) {
            return false;
        }
    }
    
    return true;
}

// Helper class for switch analysis
static class SwitchAnalysis {
    String patternType;
    String contentPattern;  // NEW
    int caseCount;
    double avgLinesPerCase;
    boolean hasComplexLogic;
    boolean hasObjectCreation;
    int complexityScore;
}

private static SwitchAnalysis analyzeSwitchComplexity(SwitchStmt switchStmt) {
    SwitchAnalysis analysis = new SwitchAnalysis();
    List<SwitchEntry> entries = switchStmt.getEntries();
    
    int totalCases = 0;
    int totalLines = 0;
    int casesWithLogic = 0;
    int casesWithObjects = 0;
    
    for (SwitchEntry entry : entries) {
        if (entry.getLabels().isEmpty()) continue;
        
        totalCases++;
        int caseLines = 0;
        boolean hasLogic = false;
        boolean hasObjects = false;
        
        for (Statement stmt : entry.getStatements()) {
            String stmtStr = stmt.toString();
            caseLines += countNonEmptyLines(stmtStr);
            
            // Check for complex logic
            if (stmt instanceof IfStmt || stmt instanceof ForStmt || 
                stmt instanceof WhileStmt || stmt instanceof DoStmt ||
                stmtStr.contains("++") || stmtStr.contains("--") ||
                stmtStr.contains("+=") || stmtStr.contains("-=")) {
                hasLogic = true;
            }
            
            // Check for object creation
            if (stmtStr.contains("new ") || stmtStr.contains(".create") ||
                stmtStr.contains(".builder()") || stmtStr.contains("Factory")) {
                hasObjects = true;
            }
        }
        
        totalLines += caseLines;
        if (hasLogic) casesWithLogic++;
        if (hasObjects) casesWithObjects++;
    }
    
    // SET BASIC ANALYSIS FIELDS
    analysis.caseCount = totalCases;
    analysis.avgLinesPerCase = totalCases > 0 ? (double) totalLines / totalCases : 0;
    analysis.hasComplexLogic = casesWithLogic > 0;
    analysis.hasObjectCreation = casesWithObjects > 0;
    
    // Determine pattern type
    if (casesWithObjects >= totalCases * 0.8 && !analysis.hasComplexLogic) {
        analysis.patternType = "FACTORY_PATTERN";
    } else if (casesWithLogic >= totalCases * 0.7 && analysis.avgLinesPerCase >= 3) {
        analysis.patternType = "STATE_MACHINE";
    } else if (analysis.avgLinesPerCase <= 2 && totalCases <= 3) {
        analysis.patternType = "SIMPLE_DISPATCH";
    } else {
        analysis.patternType = "MIXED_LOGIC";
    }
    
    // Calculate initial complexity score
    analysis.complexityScore = (int) (analysis.avgLinesPerCase * 5) + 
                               (casesWithLogic * 3) + 
                               (casesWithObjects * 2) + 
                               totalCases;
    
    // ========== NEW: CONTENT ANALYSIS ==========
    analysis.contentPattern = analyzeSwitchContent(switchStmt);
    
    // ========== ADJUST BASED ON CONTENT ==========
    if (analysis.contentPattern.equals("STRING_MAPPING") || 
        analysis.contentPattern.equals("SIMPLE_MAPPING")) {
        // Simple mappings are much less complex
        analysis.complexityScore = Math.max(1, analysis.complexityScore / 3);
        analysis.hasComplexLogic = false; // Override - simple returns aren't complex
    } else if (analysis.contentPattern.equals("METHOD_DISPATCH")) {
        // Method dispatch is somewhat complex
        if (!analysis.hasComplexLogic && analysis.caseCount <= 4) {
            analysis.complexityScore = Math.max(1, analysis.complexityScore / 2);
        }
    }
    // COMPLEX_LOGIC and STATE_CHANGE keep their original scores
    
    return analysis;
}

private static String analyzeSwitchContent(SwitchStmt switchStmt) {
    List<SwitchEntry> entries = switchStmt.getEntries();
    
    int stringReturns = 0;
    int methodCalls = 0;
    int assignments = 0;
    int complexLogic = 0;
    int totalCases = 0;
    boolean allReturn = true;
    boolean allSameType = true;
    String firstReturnType = null;
    
    // First pass: count non-default cases
    for (SwitchEntry entry : entries) {
        if (!entry.getLabels().isEmpty()) {
            totalCases++;
        }
    }
    
    // If no actual cases (only default), return early
    if (totalCases == 0) {
        return "DEFAULT_ONLY";
    }
    
    // Second pass: analyze content
    for (SwitchEntry entry : entries) {
        List<Statement> statements = entry.getStatements();
        if (statements.isEmpty()) {
            continue;
        }
        
        // Check last statement type
        Statement lastStmt = statements.get(statements.size() - 1);
        if (lastStmt instanceof ReturnStmt) {
            ReturnStmt returnStmt = (ReturnStmt) lastStmt;
            if (returnStmt.getExpression().isPresent()) {
                Expression expr = returnStmt.getExpression().get();
                
                if (expr instanceof StringLiteralExpr) {
                    stringReturns++;
                    if (firstReturnType == null) {
                        firstReturnType = "STRING_LITERAL";
                    } else if (!firstReturnType.equals("STRING_LITERAL")) {
                        allSameType = false;
                    }
                } else if (expr instanceof NameExpr || expr instanceof FieldAccessExpr) {
                    if (firstReturnType == null) {
                        firstReturnType = "VARIABLE";
                    } else if (!firstReturnType.equals("VARIABLE")) {
                        allSameType = false;
                    }
                } else if (expr instanceof MethodCallExpr) {
                    methodCalls++;
                    if (firstReturnType == null) {
                        firstReturnType = "METHOD_CALL";
                    } else if (!firstReturnType.equals("METHOD_CALL")) {
                        allSameType = false;
                    }
                }
            }
        } else {
            allReturn = false;
        }
        
        // Check for complex logic
        for (Statement stmt : statements) {
            if (stmt instanceof IfStmt || stmt instanceof ForStmt || 
                stmt instanceof WhileStmt || stmt instanceof DoStmt) {
                complexLogic++;
                break;
            }
            if (stmt instanceof ExpressionStmt) {
                ExpressionStmt exprStmt = (ExpressionStmt) stmt;
                if (exprStmt.getExpression() instanceof AssignExpr) {
                    assignments++;
                } else if (exprStmt.getExpression() instanceof MethodCallExpr) {
                    methodCalls++;
                }
            }
        }
    }
    
    // Determine pattern
    if (allReturn && stringReturns == totalCases) return "STRING_MAPPING";
    if (allReturn && allSameType && complexLogic == 0) return "SIMPLE_MAPPING";
    if (methodCalls > totalCases * 0.5) return "METHOD_DISPATCH";
    if (complexLogic > 0) return "COMPLEX_LOGIC";
    if (assignments > 0) return "STATE_CHANGE";
    
    return "MIXED";
}



    private static boolean isJustifiedIdenticalOverride(MethodDeclaration childMethod,
                                                       ClassOrInterfaceDeclaration childClass,
                                                       ClassOrInterfaceDeclaration parentClass,
                                                       Map<String, ClassOrInterfaceDeclaration> classMap) {
        
        String name = childMethod.getNameAsString();
        if (OBJECT_METHOD_NAMES.contains(name)) return true;
        if (FRAMEWORK_METHOD_NAMES.contains(name)) return true;

        String methodName = childMethod.getNameAsString();
        
        for (MethodDeclaration parentMethod : parentClass.getMethodsByName(methodName)) {
            if (parentMethod.isAbstract()) {
                if (parametersMatch(parentMethod, childMethod)) {
                    return true;
                }
            }
        }
        
        if (methodFromInterface(methodName, childMethod.getParameters(), parentClass, classMap)) {
            return true;
        }
        
        if (methodName.startsWith("get") && methodName.length() > 3) {
            String fieldName = Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
            if (classHasField(childClass, fieldName)) {
                return true;
            }
        }
        
        if (methodName.startsWith("set") && methodName.length() > 3) {
            String fieldName = Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
            if (classHasField(childClass, fieldName)) {
                return true;
            }
        }
        
        if (childMethod.getBody().isPresent()) {
            String body = childMethod.getBody().get().toString();
            Set<String> childFields = getAllFieldNames(childClass);
            for (String field : childFields) {
                if (body.contains(field) || body.contains("this." + field)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private static boolean methodFromInterface(String methodName, List<Parameter> parameters,
                                              ClassOrInterfaceDeclaration parentClass,
                                              Map<String, ClassOrInterfaceDeclaration> classMap) {
        
        Set<String> allInterfaces = new HashSet<>();
        collectAllInterfaces(parentClass, allInterfaces, classMap);
        
        for (String interfaceName : allInterfaces) {
            ClassOrInterfaceDeclaration interfaceDecl = classMap.get(interfaceName);
            if (interfaceDecl != null && interfaceDecl.isInterface()) {
                for (MethodDeclaration interfaceMethod : interfaceDecl.getMethods()) {
                    if (interfaceMethod.getNameAsString().equals(methodName)) {
                        if (parametersMatch(interfaceMethod, parameters)) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }

    private static void collectAllInterfaces(ClassOrInterfaceDeclaration clazz,
                                            Set<String> interfaces,
                                            Map<String, ClassOrInterfaceDeclaration> classMap) {
        
        if (clazz == null) return;
        
        for (ClassOrInterfaceType ifaceType : clazz.getImplementedTypes()) {
            String ifaceName = ifaceType.getNameAsString();
            if (interfaces.add(ifaceName)) {
                ClassOrInterfaceDeclaration ifaceDecl = classMap.get(ifaceName);
                if (ifaceDecl != null) {
                    collectAllInterfaces(ifaceDecl, interfaces, classMap);
                }
            }
        }
        
        if (!clazz.getExtendedTypes().isEmpty()) {
            String parentName = clazz.getExtendedTypes(0).getNameAsString();
            ClassOrInterfaceDeclaration parentDecl = classMap.get(parentName);
            if (parentDecl != null) {
                collectAllInterfaces(parentDecl, interfaces, classMap);
            }
        }
    }

    private static boolean parametersMatch(MethodDeclaration interfaceMethod, 
                                          List<Parameter> childParams) {
        if (interfaceMethod.getParameters().size() != childParams.size()) {
            return false;
        }
        
        for (int i = 0; i < interfaceMethod.getParameters().size(); i++) {
            String ifaceParamType = interfaceMethod.getParameter(i).getType().asString();
            String childParamType = childParams.get(i).getType().asString();
            
            if (!ifaceParamType.equals(childParamType)) {
                return false;
            }
        }
        
        return true;
    }

    private static boolean parametersMatch(MethodDeclaration m1, MethodDeclaration m2) {
        if (m1.getParameters().size() != m2.getParameters().size()) return false;

        for (int i = 0; i < m1.getParameters().size(); i++) {
            if (!m1.getParameter(i).getType().equals(m2.getParameter(i).getType())) {
                return false;
            }
        }
        return true;
    }

    private static boolean classHasField(ClassOrInterfaceDeclaration clazz, String fieldName) {
        return clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .anyMatch(v -> v.getNameAsString().equals(fieldName));
    }

    private static Set<String> getAllFieldNames(ClassOrInterfaceDeclaration clazz) {
        return clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .map(v -> v.getNameAsString())
            .collect(Collectors.toSet());
    }

    private static void removeAllComments(Node node) {
        node.getAllContainedComments().forEach(Comment::remove);
    }



    private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap,
                                        String studentName) {

    Map<String, Set<String>> methodToClasses = new HashMap<>();
    Map<String, Map<String, MethodDeclaration>> methodExamplesMap = new HashMap<>();

    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (isTestClass(clazz)) continue;
        if (looksLikeInternalNode(clazz)) continue;
        
        for (MethodDeclaration method : clazz.getMethods()) {
            if (isMainMethod(method) || method.isStatic()) continue;
            if (!method.isPublic()) continue;
            
            String name = method.getNameAsString();
            if (OBJECT_METHOD_NAMES.contains(name)) continue;
            if (FRAMEWORK_METHOD_NAMES.contains(name)) continue;
            
            if (method.getBody().isEmpty()) continue;
            
            int stmtCount = method.getBody().get().getStatements().size();
            if (stmtCount == 1 && method.getBody().get().getStatement(0).isReturnStmt()) {
                continue;
            }
            
            String sig = methodSignatureWithoutVisibility(method);
            methodToClasses
                .computeIfAbsent(sig, k -> new HashSet<>())
                .add(clazz.getNameAsString());
            
            // Store example method for this signature
            if (!methodExamplesMap.containsKey(sig)) {
                methodExamplesMap.put(sig, new HashMap<>());
            }
            methodExamplesMap.get(sig).put(clazz.getNameAsString(), method);
        }
    }

    // Group by sets of classes that share the same methods
    Map<Set<String>, List<String>> classGroupToMethods = new HashMap<>();
    
    for (Map.Entry<String, Set<String>> entry : methodToClasses.entrySet()) {
        Set<String> classes = entry.getValue();
        if (classes.size() < 2) continue;

        long sharedCount = methodToClasses.entrySet().stream()
            .filter(e -> e.getValue().equals(classes))
            .count();

        if (sharedCount < 2) continue;

        if (haveCommonAncestor(classes, classMap)) continue;
        
        if (isDelegationPattern(entry.getKey(), classes, classMap)) continue;

        if (classes.stream().anyMatch(c -> looksLikeInternalNode(classMap.get(c)))) continue;

        boolean anyInternal = classes.stream()
            .map(classMap::get)
            .anyMatch(c -> c != null && looksLikeInternalNode(c));

        if (anyInternal) continue;

        Set<ClassOrInterfaceDeclaration> classDecls = classes.stream()
            .map(classMap::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());

        if (sharedCount < 2) continue;

        if (!weaklyRelated(classDecls)) continue;

        // Add method to the class group
        classGroupToMethods
            .computeIfAbsent(classes, k -> new ArrayList<>())
            .add(entry.getKey());
    }
    
    // Process each class group
    for (Map.Entry<Set<String>, List<String>> entry : classGroupToMethods.entrySet()) {
        Set<String> classes = entry.getKey();
        List<String> sharedMethods = entry.getValue();
        
        if (sharedMethods.size() == 1) {
            // Single shared method
            String methodSig = sharedMethods.get(0);
            String details = "Classes define same method but do not share superclass or interface";
            addCsvRow(studentName, String.join("; ", classes),
                extractMethodName(methodSig), "Missing Inheritance",
                "HIGH", details);
            
            Map<String, MethodDeclaration> examples = methodExamplesMap.get(methodSig);
            addLLMCandidate(studentName, String.join("; ", classes),
                extractMethodName(methodSig), "PotentialMissingInheritance",
                Map.of(
                    "classes", String.join("; ", classes),
                    "sharedMethods", "1",
                    "methodSignature", methodSig,
                    "methodExample", getMethodExampleString(examples),
                    "similarityScore", String.valueOf(calculateClassSimilarity(classes, classMap)),
                    "weaklyRelated", "true",
                    "hasCommonAncestor", "false"
                ));
        } else {
            // Multiple shared methods
            String classList = String.join("; ", classes);
            String methodNames = extractMethodNames(sharedMethods);
            
            String details = sharedMethods.size() + " methods shared by classes without common superclass";
            addCsvRow(studentName, classList,
                methodNames, "Missing Inheritance",
                "HIGH", details);
            
            // Collect all method examples
            Map<String, String> allMethodExamples = new HashMap<>();
            for (String methodSig : sharedMethods) {
                Map<String, MethodDeclaration> examples = methodExamplesMap.get(methodSig);
                if (examples != null && !examples.isEmpty()) {
                    allMethodExamples.put(methodSig, getMethodExampleString(examples));
                }
            }
            
            addLLMCandidate(studentName, classList,
                methodNames, "PotentialMissingInheritanceGroup",
                Map.of(
                    "classes", classList,
                    "sharedMethodsCount", String.valueOf(sharedMethods.size()),
                    "sharedMethodNames", methodNames,
                    "methodSignatures", String.join("; ", sharedMethods),
                    "methodExamples", String.join(" | ", allMethodExamples.values()),
                    "similarityScore", String.valueOf(calculateClassSimilarity(classes, classMap)),
                    "weaklyRelated", "true",
                    "hasCommonAncestor", "false",
                    "details", "Multiple methods suggest missing inheritance hierarchy"
                ));
        }
    }
}

// Helper methods
private static String extractMethodName(String methodSig) {
    // Extract method name from signature (e.g., "int calculate(int)" -> "calculate")
    int parenIndex = methodSig.indexOf('(');
    if (parenIndex == -1) return methodSig;
    
    String beforeParen = methodSig.substring(0, parenIndex).trim();
    int lastSpace = beforeParen.lastIndexOf(' ');
    if (lastSpace == -1) return beforeParen;
    
    return beforeParen.substring(lastSpace + 1);
}

private static String extractMethodNames(List<String> methodSigs) {
    return methodSigs.stream()
        .map(methodSig -> extractMethodName(methodSig))
        .collect(Collectors.joining("; "));
}

private static String getMethodExampleString(Map<String, MethodDeclaration> examples) {
    if (examples == null || examples.isEmpty()) return "";
    
    // Get first example
    MethodDeclaration example = examples.values().iterator().next();
    String declaration = example.getDeclarationAsString();
    // Truncate if too long
    return declaration.length() > 100 ? declaration.substring(0, 100) + "..." : declaration;
}



private static int calculateClassSimilarity(Set<String> classes, 
                                          Map<String, ClassOrInterfaceDeclaration> classMap) {
    // Simple similarity metric (0-100)
    int totalFields = 0;
    int commonFields = 0;
    
    // Count field overlap
    Set<String> allFields = new HashSet<>();
    Map<String, Set<String>> classFields = new HashMap<>();
    
    for (String className : classes) {
        ClassOrInterfaceDeclaration clazz = classMap.get(className);
        if (clazz != null) {
            Set<String> fields = getAllFieldNames(clazz);
            classFields.put(className, fields);
            allFields.addAll(fields);
        }
    }
    
    // Check which fields are in all classes
    for (String field : allFields) {
        boolean inAll = true;
        for (Set<String> fields : classFields.values()) {
            if (!fields.contains(field)) {
                inAll = false;
                break;
            }
        }
        if (inAll) commonFields++;
    }
    
    totalFields = allFields.size();
    return totalFields > 0 ? (commonFields * 100 / totalFields) : 0;
}

    private static boolean weaklyRelated(Set<ClassOrInterfaceDeclaration> classes) {
        List<ClassOrInterfaceDeclaration> list = new ArrayList<>(classes);

        for (int i = 0; i < list.size(); i++) {
            for (int j = i + 1; j < list.size(); j++) {
                String a = list.get(i).getNameAsString().toLowerCase();
                String b = list.get(j).getNameAsString().toLowerCase();
                if (a.contains(b) || b.contains(a)) return true;

                Set<String> typesA = list.get(i).findAll(ClassOrInterfaceType.class)
                    .stream().map(t -> t.getNameAsString()).collect(Collectors.toSet());

                Set<String> typesB = list.get(j).findAll(ClassOrInterfaceType.class)
                    .stream().map(t -> t.getNameAsString()).collect(Collectors.toSet());

                typesA.retainAll(typesB);
                if (!typesA.isEmpty()) return true;
            }
        }
        return false;
    }

    private static boolean isTestClass(ClassOrInterfaceDeclaration clazz) {
        if (clazz.getNameAsString().endsWith("Test")) return true;
        if (!clazz.findAll(MarkerAnnotationExpr.class).isEmpty()) return true;
        
        return clazz.findCompilationUnit()
            .flatMap(cu -> cu.getImports().stream()
                .map(i -> i.getNameAsString())
                .filter(n -> n.startsWith("org.junit"))
                .findAny())
            .isPresent();
    }

    private static boolean looksLikeInternalNode(ClassOrInterfaceDeclaration clazz) {
        boolean isGeneric = !clazz.getTypeParameters().isEmpty();
        boolean hasNextField = clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .anyMatch(v -> v.getNameAsString().equalsIgnoreCase("next"));
        boolean hasValueField = clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .anyMatch(v -> v.getNameAsString().equalsIgnoreCase("value"));

        return isGeneric && (hasNextField || hasValueField);
    }

    private static boolean isDelegationPattern(String methodSignature, 
                                              Set<String> classNames, 
                                              Map<String, ClassOrInterfaceDeclaration> classMap) {
        
        if (classNames.size() != 2) return false;
        
        List<String> classesList = new ArrayList<>(classNames);
        String classA = classesList.get(0);
        String classB = classesList.get(1);
        
        MethodDeclaration methodA = findMethod(classA, methodSignature, classMap);
        MethodDeclaration methodB = findMethod(classB, methodSignature, classMap);
        
        if (methodA == null || methodB == null) return false;
        
        return isSimpleDelegate(methodA, classB, classMap) || 
               isSimpleDelegate(methodB, classA, classMap);
    }

    private static MethodDeclaration findMethod(String className, 
                                               String methodSignature, 
                                               Map<String, ClassOrInterfaceDeclaration> classMap) {
        ClassOrInterfaceDeclaration clazz = classMap.get(className);
        if (clazz == null) return null;
        
        for (MethodDeclaration method : clazz.getMethods()) {
            if (methodSignatureWithoutVisibility(method).equals(methodSignature)) {
                return method;
            }
        }
        return null;
    }

    private static boolean isSimpleDelegate(MethodDeclaration method, 
                                          String delegateClassName,
                                          Map<String, ClassOrInterfaceDeclaration> classMap) {
        if (!method.getBody().isPresent()) return false;
        
        BlockStmt body = method.getBody().get();
        String declaringClass = ((ClassOrInterfaceDeclaration) method.getParentNode().get()).getNameAsString();
        ClassOrInterfaceDeclaration declaringClassDecl = classMap.get(declaringClass);
        
        boolean hasDelegateField = false;
        for (FieldDeclaration field : declaringClassDecl.getFields()) {
            String fieldType = field.getElementType().asString();
            if (fieldType.equals(delegateClassName) || 
                fieldType.endsWith("." + delegateClassName)) {
                hasDelegateField = true;
                break;
            }
        }
        
        if (!hasDelegateField) return false;
        
        List<Statement> statements = body.getStatements();
        if (statements.size() != 1) return false;
        
        Statement stmt = statements.get(0);
        if (stmt.isExpressionStmt()) {
            ExpressionStmt exprStmt = stmt.asExpressionStmt();
            Expression expr = exprStmt.getExpression();
            
            if (expr.isMethodCallExpr()) {
                MethodCallExpr call = expr.asMethodCallExpr();
                if (call.getScope().isPresent()) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private static boolean haveCommonAncestor(Set<String> classNames, Map<String, ClassOrInterfaceDeclaration> classMap) {
        if (oneIsAncestorOfAnother(classNames, classMap)) return true;
        if (shareCommonAncestor(classNames, classMap)) return true;
        return false;
    }

    private static boolean oneIsAncestorOfAnother(Set<String> classNames, Map<String, ClassOrInterfaceDeclaration> classMap) {
        for (String childName : classNames) {
            Set<String> ancestors = getAllAncestors(childName, classMap);
            for (String potentialParent : classNames) {
                if (!childName.equals(potentialParent) && ancestors.contains(potentialParent)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean shareCommonAncestor(Set<String> classNames, Map<String, ClassOrInterfaceDeclaration> classMap) {
        if (classNames.isEmpty()) return false;

        List<Set<String>> allAncestors = new ArrayList<>();
        for (String className : classNames) {
            allAncestors.add(getAllAncestors(className, classMap));
        }

        Set<String> common = new HashSet<>(allAncestors.get(0));
        for (Set<String> s : allAncestors) {
            common.retainAll(s);
        }
        return !common.isEmpty();
    }

    private static Set<String> getAllAncestors(String className, Map<String, ClassOrInterfaceDeclaration> classMap) {
        Set<String> ancestors = new HashSet<>();
        ClassOrInterfaceDeclaration clazz = classMap.get(className);

        if (clazz == null) return ancestors;

        if (!clazz.getExtendedTypes().isEmpty()) {
            String parent = clazz.getExtendedTypes(0).getNameAsString();
            if (!parent.equals("Object") && classMap.containsKey(parent)) {
                ancestors.add(parent);
                ancestors.addAll(getAllAncestors(parent, classMap));
            }
        }

        for (ClassOrInterfaceType iface : clazz.getImplementedTypes()) {
            String ifaceName = iface.getNameAsString();
            ancestors.add(ifaceName);
            if (classMap.containsKey(ifaceName)) {
                ancestors.addAll(getAllAncestors(ifaceName, classMap));
            }
        }

        return ancestors;
    }

    private static String methodSignatureWithoutVisibility(MethodDeclaration m) {
        String returnType = m.getType().toString().replaceAll("\\s+", "");
        String params = m.getParameters().stream()
                         .map(p -> p.getType().toString().replaceAll("\\s+", ""))
                         .reduce((a, b) -> a + "," + b)
                         .orElse("");
        return returnType + " " + m.getNameAsString() + "(" + params + ")";
    }

    private static boolean isMainMethod(MethodDeclaration m) {
        return m.getNameAsString().equals("main")
                && m.getParameters().size() == 1
                && m.getParameter(0).getType().asString().equals("String[]");
    }

    private static void detectRedundantSuperclass(Map<String, ClassOrInterfaceDeclaration> classMap, 
                                             String studentName) {
    
    Map<String, List<String>> redundantInheritanceGroups = new HashMap<>();
    Map<String, String> parentMap = new HashMap<>();
    
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (clazz.getExtendedTypes().isEmpty()) continue;

        String parentName = clazz.getExtendedTypes().get(0).getNameAsString();
        
        if (parentName.equals("Object")) {
            continue;
        }

        ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
        if (parentClass == null) continue;

        Set<String> overridableMethods = new HashSet<>();
        for (MethodDeclaration pm : parentClass.getMethods()) {
            if (!pm.isPrivate() && !pm.isFinal()) {
                overridableMethods.add(getMethodSignature(pm));
            }
        }
        
        if (overridableMethods.isEmpty()) {
            if (!hasValidExtensionReason(clazz, parentClass)) {
                // Store for grouping
                String groupKey = studentName + "|" + parentName;
                redundantInheritanceGroups
                    .computeIfAbsent(groupKey, k -> new ArrayList<>())
                    .add(clazz.getNameAsString());
                parentMap.put(groupKey, parentName);
            }
            continue;
        }
        
        boolean overridesAny = false;
        for (MethodDeclaration cm : clazz.getMethods()) {
            if (overridableMethods.contains(getMethodSignature(cm))) {
                overridesAny = true;
                break;
            }
        }
        
        if (!overridesAny && !hasValidExtensionReason(clazz, parentClass)) {
            // Store for grouping
            String groupKey = studentName + "|" + parentName;
            redundantInheritanceGroups
                .computeIfAbsent(groupKey, k -> new ArrayList<>())
                .add(clazz.getNameAsString());
            parentMap.put(groupKey, parentName);
        }
    }
    
    // Process grouped redundant inheritance cases
    for (Map.Entry<String, List<String>> entry : redundantInheritanceGroups.entrySet()) {
        String groupKey = entry.getKey();
        List<String> childClasses = entry.getValue();
        String parentName = parentMap.get(groupKey);
        
        if (childClasses.size() == 1) {
            // Single class
            String childName = childClasses.get(0);
            String details = "Class inherits but does not override/reuse superclass methods";
            addCsvRow(studentName, childName,
                "", "Redundant Inheritance",
                "HIGH", details);
            
            addLLMCandidate(studentName, childName,
                "", "RedundantInheritance",
                Map.of(
                    "details", details,
                    "parentClass", parentName,
                    "childClass", childName,
                    "severity", "HIGH"
                ));
        } else {
            // Multiple classes with same redundant inheritance pattern
            String classList = String.join("; ", childClasses);
            String details = childClasses.size() + " classes redundantly inherit from " + parentName;
            
            addCsvRow(studentName, classList,
                "", "Redundant Inheritance Group",
                "HIGH", details);
            
            addLLMCandidate(studentName, classList,
                "", "RedundantInheritanceGroup",
                Map.of(
                    "details", details,
                    "parentClass", parentName,
                    "childClasses", classList,
                    "childCount", String.valueOf(childClasses.size()),
                    "severity", "HIGH",
                    "pattern", "Multiple classes with same redundant inheritance"
                ));
        }
    }
}

// Helper method to get method signature
private static String getMethodSignature(MethodDeclaration m) {
    StringBuilder sig = new StringBuilder();
    sig.append(m.getNameAsString()).append("(");
    
    for (int i = 0; i < m.getParameters().size(); i++) {
        if (i > 0) sig.append(",");
        sig.append(m.getParameter(i).getType().asString());
    }
    
    sig.append(")");
    return sig.toString();
}

    private static boolean hasValidExtensionReason(ClassOrInterfaceDeclaration child, 
                                                  ClassOrInterfaceDeclaration parent) {
        
        if (!child.getFields().isEmpty()) {
            return true;
        }
        
        for (ConstructorDeclaration constructor : child.getConstructors()) {
            BlockStmt body = constructor.getBody();
            for (Statement stmt : body.getStatements()) {
                if (stmt.isExplicitConstructorInvocationStmt()) {
                    return true;
                }
            }
        }
        
        Set<String> parentNonPrivateFields = new HashSet<>();
        for (FieldDeclaration field : parent.getFields()) {
            if (!field.isPrivate()) {
                for (VariableDeclarator var : field.getVariables()) {
                    parentNonPrivateFields.add(var.getNameAsString());
                }
            }
        }
        
        for (MethodDeclaration method : child.getMethods()) {
            Optional<BlockStmt> bodyOpt = method.getBody();
            if (bodyOpt.isPresent()) {
                BlockStmt body = bodyOpt.get();
                String bodyString = body.toString();
                for (String fieldName : parentNonPrivateFields) {
                    if (bodyString.contains(fieldName)) {
                        return true;
                    }
                }
            }
        }
        
        if (parent.isAbstract() || parent.isInterface()) {
            return true;
        }
        
        for (FieldDeclaration field : child.getFields()) {
            for (VariableDeclarator var : field.getVariables()) {
                if (var.getInitializer().isPresent()) {
                    String initializer = var.getInitializer().get().toString();
                    for (String parentField : parentNonPrivateFields) {
                        if (initializer.contains(parentField)) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }

    private static void flagRedundantInheritance(String studentName, 
                                                String childName, String parentName) {
        System.out.printf("Redundant inheritance: Class %s inherits from %s but does not override or reuse any superclass method.%n",
                childName, parentName);
                

        csvRows.add(new String[]{
                studentName,
                childName,
                "",
                "Redundant Inheritance",
                "HIGH",
                "Class inherits but does not override/reuse superclass methods"
        });

        addLLMCandidate(studentName, childName, "", "RedundantInheritance",
        Map.of(
            "details", "Class inherits but does not override/reuse superclass methods",
            "parentClass", parentName,
            "childClass", childName,
            "severity", "HIGH"
        ));
    }
}