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

    private static List<String[]> csvRows = new ArrayList<>();
    private static final Set<String> FRAMEWORK_METHOD_NAMES = Set.of("setUp", "tearDown");
    private static final Set<String> OBJECT_METHOD_NAMES = Set.of("equals", "hashCode", "toString");
    
    // NEW: List for LLM candidates
    private static List<Map<String, Object>> llmCandidates = new ArrayList<>();

    private static void addCsvRow(String studentName, String className, 
                             String methodName, String issueType, 
                             String severity, String details) {
    
    csvRows.add(new String[]{
        studentName,
        className,
        methodName,
        issueType,
        severity,
        details
    });
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
        File submissionsDir = new File("C:\\Users\\GGPC\\Downloads\\escaipe-room-beta-anonymised\\escaipe-room-beta-anonymised");
        
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
                            fileToStudent.put(f.getAbsolutePath(), studentName);
                        });
                } catch (IOException e) {
                    System.err.println("Failed walking " + studentDir + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }

        System.out.println("Found " + javaFiles.size() + " Java files across " + 
                          (studentDirs != null ? studentDirs.length : 0) + " students");

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
                groupedClassMaps.get(studentName).put(clazz.getNameAsString(), clazz);
            }
            validUnits.add(cu);
        }

        Set<String> allEnumNames = collectAllEnumNames(validUnits);

        System.out.println("\nParsed classes (grouped by student):");
        // Perform detections per student
        for (Map.Entry<String, Map<String, ClassOrInterfaceDeclaration>> entry : groupedClassMaps.entrySet()) {
    String studentName = entry.getKey();
    String assignmentId = extractAssignmentId(studentName);
    Map<String, ClassOrInterfaceDeclaration> classMap = entry.getValue();

    System.out.println("\n=== Running detections for " + studentName + " (Assignment: " + assignmentId + ") ===");

    // ========== PER-CLASS DETECTIONS ==========
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        analyzeEnumUsage(clazz, studentName);

        if (hasTypeField(clazz)) {
            detectTypeCheckingInMethods(clazz, studentName);
        }
        
        
    }

    // ========== INHERITANCE-BASED DETECTIONS ==========
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {

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

        writeDetectorCandidates("llm_candidates_detector.json");
        writeLLMCandidates("llm_candidates.json");
        
        
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
    
    for (MethodDeclaration method : clazz.getMethods()) {
        Optional<BlockStmt> body = method.getBody();
        if (body.isEmpty()) continue;
        
        // Find ALL switches in this method
        List<SwitchStmt> switches = body.get().findAll(SwitchStmt.class);
        if (switches.isEmpty()) {
            continue; // No switches in this method
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
            }
        }
        
        // Calculate averages
        double avgCases = totalSwitches > 0 ? (double) totalCases / totalSwitches : 0;
        double avgComplexity = totalSwitches > 0 ? totalComplexity / totalSwitches : 0;
        
        // Determine overall pattern based on ALL switches in this method
        String overallPattern = determineOverallPattern(switchAnalyses);
        
        // Output ONE CSV entry for this method (aggregating all switches)
        String details = String.format(
            "Method contains %d switch(es) with %d total cases, avg %.1f cases/switch, pattern: %s",
            totalSwitches, totalCases, avgCases, overallPattern
        );
        
        addCsvRow(studentName, clazz.getNameAsString(),
            method.getNameAsString(), // Method name
            "Switch Complexity",
            highestSeverity, // Use the highest severity among switches
            details);
        
        // Create switch breakdown list first
        List<Map<String, Object>> switchBreakdown = new ArrayList<>();
        for (SwitchAnalysis analysis : switchAnalyses) {
            Map<String, Object> switchInfo = new HashMap<>();
            switchInfo.put("patternType", analysis.patternType);
            switchInfo.put("caseCount", analysis.caseCount);
            switchInfo.put("complexityScore", analysis.complexityScore);
            switchInfo.put("hasComplexLogic", analysis.hasComplexLogic);
            switchInfo.put("hasObjectCreation", analysis.hasObjectCreation);
            switchBreakdown.add(switchInfo);
        }

        // Create evidence map using HashMap (no size limit)
        Map<String, Object> evidence = new HashMap<>();
        evidence.put("totalSwitches", String.valueOf(totalSwitches));
        evidence.put("totalCases", String.valueOf(totalCases));
        evidence.put("avgCasesPerSwitch", String.format("%.1f", avgCases));
        evidence.put("avgComplexityScore", String.format("%.1f", avgComplexity));
        evidence.put("overallPattern", overallPattern);
        evidence.put("hasComplexLogic", String.valueOf(hasComplexLogic));
        evidence.put("hasObjectCreation", String.valueOf(hasObjectCreation));
        evidence.put("highestSeverity", highestSeverity);
        evidence.put("methodSignature", method.getDeclarationAsString());
        evidence.put("switchBreakdown", switchBreakdown);
        evidence.put("suggestion", getSuggestionForSwitches(totalSwitches, avgCases, overallPattern));

        // Now call addLLMCandidate
        addLLMCandidate(studentName, clazz.getNameAsString(),
            method.getNameAsString(), "SwitchComplexity", evidence);
        
        // Check if chains on enum-like comparisons (separate detection)
        analyzeIfChainsForPolymorphism(method, clazz, studentName);
    }
}

private static String determineOverallPattern(List<SwitchAnalysis> analyses) {
    if (analyses.isEmpty()) return "NO_SWITCHES";
    
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
        List<SwitchEntry> entries = switchStmt.getEntries();
        
        int totalLines = 0;
        int totalCases = 0;
        int casesWithExecution = 0;
        int casesWithObjectCreation = 0;
        
        for (SwitchEntry entry : entries) {
            if (entry.getLabels().isEmpty()) continue;
            totalCases++;
            boolean hasExecution = false;
            boolean hasObjectCreation = false;
            
            for (Statement stmt : entry.getStatements()) {
                String stmtStr = stmt.toString().toLowerCase();
                totalLines += stmtStr.split("\n").length;
                
                if (stmtStr.contains("round++") ||
                    stmtStr.contains("++") ||
                    stmtStr.contains("--") ||
                    stmtStr.contains(".add(") ||
                    stmtStr.contains("if(") ||
                    stmtStr.contains("while(") ||
                    stmtStr.contains("print")) {
                    hasExecution = true;
                }
                
                if (stmtStr.contains("new ") || stmtStr.contains("factory")) {
                    hasObjectCreation = true;
                }
            }
            
            if (hasExecution) casesWithExecution++;
            if (hasObjectCreation) casesWithObjectCreation++;
        }
        
        if (totalCases == 0) return "LOW";
        double avgLines = (double) totalLines / totalCases;

        if (casesWithExecution > totalCases * 0.7 || avgLines >= 5.0) {
            return "HIGH";
        }
        
        if (casesWithExecution > 0 && casesWithObjectCreation > 0) {
            return "MEDIUM";
        }
        
        if (casesWithObjectCreation >= totalCases * 0.7 && avgLines <= 3.0) {
            return "LOW";
        }
        
        return "MEDIUM";
    }

    private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, 
                                            ClassOrInterfaceDeclaration parent, 
                                            String studentName,
                                            Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    Map<String, MethodDeclaration> parentMethods = new HashMap<>();
    for (MethodDeclaration pm : parent.getMethods()) {
        parentMethods.put(pm.getSignature().asString(), pm);
    }

    for (MethodDeclaration childMethod : child.getMethods()) {
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
                    // Output to CSV (simple format)
                    String details = "Identical to parent method";
                    addCsvRow(studentName, child.getNameAsString(),
                        childMethod.getNameAsString(), "Redundant Override",
                        "MEDIUM", details);
                    
                    // Output to LLM candidates with richer context
                    addLLMCandidate(studentName, child.getNameAsString(),
                        childMethod.getNameAsString(), "RedundantOverride",
                        Map.of(
                            "parentSignature", parentMethod.getDeclarationAsString(),
                            "childSignature", childMethod.getDeclarationAsString(),
                            "bodySimilarity", "100", // 100% identical
                            "parentIsAbstract", String.valueOf(parentMethod.isAbstract()),
                            "methodComplexity", assessMethodComplexity(parentMethod),
                            "isGetterSetter", String.valueOf(isGetterOrSetter(childMethod)),
                            "isConstructor", String.valueOf(checkIfConstructor(childMethod))
                        ));
                }
            }
        }
    }
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
        if (entry.getLabels().isEmpty()) continue; // Default case
        
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
    
    // Calculate complexity score
    analysis.complexityScore = (int) (analysis.avgLinesPerCase * 5) + 
                               (casesWithLogic * 3) + 
                               (casesWithObjects * 2) + 
                               totalCases;
    
    return analysis;
}

private static void analyzeIfChainsForPolymorphism(MethodDeclaration method, 
                                                  ClassOrInterfaceDeclaration clazz, 
                                                  String studentName) {
    BlockStmt body = method.getBody().orElse(null);
    if (body == null) return;
    
    List<IfStmt> ifStatements = body.findAll(IfStmt.class);
    if (ifStatements.size() < 2) return; // Need at least 2 ifs to be a chain
    
    // Check for chains of if-else checking the same variable
    Map<String, Integer> varCheckCounts = new HashMap<>();
    for (IfStmt ifStmt : ifStatements) {
        Expression cond = ifStmt.getCondition();
        
        // Check for instanceof or .equals comparisons
        if (cond instanceof InstanceOfExpr) {
            InstanceOfExpr instanceOf = (InstanceOfExpr) cond;
            String varName = instanceOf.getExpression().toString();
            varCheckCounts.put(varName, varCheckCounts.getOrDefault(varName, 0) + 1);
        } else if (cond instanceof MethodCallExpr) {
            MethodCallExpr call = (MethodCallExpr) cond;
            if (call.getNameAsString().equals("equals")) {
                if (call.getScope().isPresent()) {
                    String varName = call.getScope().get().toString();
                    varCheckCounts.put(varName, varCheckCounts.getOrDefault(varName, 0) + 1);
                }
            }
        } else if (cond instanceof BinaryExpr) {
            BinaryExpr binary = (BinaryExpr) cond;
            if (binary.getOperator() == BinaryExpr.Operator.EQUALS ||
                binary.getOperator() == BinaryExpr.Operator.NOT_EQUALS) {
                // Check if one side is a variable and the other is a constant/type
                Expression left = binary.getLeft();
                Expression right = binary.getRight();
                
                if (left instanceof NameExpr) {
                    String varName = ((NameExpr) left).getNameAsString();
                    if (right instanceof FieldAccessExpr || 
                        right instanceof NameExpr && 
                        Character.isUpperCase(right.toString().charAt(0))) {
                        varCheckCounts.put(varName, varCheckCounts.getOrDefault(varName, 0) + 1);
                    }
                } else if (right instanceof NameExpr) {
                    String varName = ((NameExpr) right).getNameAsString();
                    if (left instanceof FieldAccessExpr || 
                        left instanceof NameExpr && 
                        Character.isUpperCase(left.toString().charAt(0))) {
                        varCheckCounts.put(varName, varCheckCounts.getOrDefault(varName, 0) + 1);
                    }
                }
            }
        }
    }
    
    // Report suspicious chains
    for (Map.Entry<String, Integer> entry : varCheckCounts.entrySet()) {
        if (entry.getValue() >= 3) { // Chain of 3+ checks on same variable
            String details = "Chained type checks on variable: " + entry.getKey() + 
                           " (" + entry.getValue() + " checks)";
            addCsvRow(studentName, clazz.getNameAsString(),
                method.getNameAsString(), "TypeCheckingChain",
                "MEDIUM", details);
            addLLMCandidate(studentName, clazz.getNameAsString(),
                method.getNameAsString(), "TypeCheckingChain",
                Map.of(
                    "variable", entry.getKey(),
                    "checkCount", String.valueOf(entry.getValue()),
                    "pattern", "CHAINED_TYPE_CHECKS",
                    "suggestion", "Consider polymorphism instead of explicit type checking"
                ));
        }
    }
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

    private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap,
                                            String studentName) {

    Map<String, Set<String>> methodToClasses = new HashMap<>();

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
        }
    }

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

        // Output to CSV (simple format)
        String details = "Classes define same method but do not share superclass or interface";
        addCsvRow(studentName, String.join(";", classes),
            entry.getKey(), "Missing Inheritance",
            "HIGH", details);
        
        // Output to LLM candidates with richer context
        addLLMCandidate(studentName, String.join(";", classes),
            entry.getKey(), "PotentialMissingInheritance",
            Map.of(
                "classes", String.join(";", classes),
                "sharedMethods", String.valueOf(sharedCount),
                "methodExamples", getExampleMethods(entry.getKey(), classes, classMap),
                "similarityScore", String.valueOf(calculateClassSimilarity(classes, classMap)),
                "weaklyRelated", "true",
                "hasCommonAncestor", "false"
            ));
    }
}


    private static String getExampleMethods(String methodSig, Set<String> classes, 
                                       Map<String, ClassOrInterfaceDeclaration> classMap) {
    List<String> examples = new ArrayList<>();
    for (String className : classes) {
        ClassOrInterfaceDeclaration clazz = classMap.get(className);
        if (clazz != null) {
            // Find the method and get a preview
            for (MethodDeclaration method : clazz.getMethods()) {
                if (methodSignatureWithoutVisibility(method).equals(methodSig)) {
                    examples.add(method.getDeclarationAsString());
                    break;
                }
            }
        }
    }
    return String.join(", ", examples.subList(0, Math.min(3, examples.size())));
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
                    flagRedundantInheritance(studentName, clazz.getNameAsString(), parentName);
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
                flagRedundantInheritance(studentName, clazz.getNameAsString(), parentName);
            }
        }
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
    }
}