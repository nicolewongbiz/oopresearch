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
    String assignmentId = extractAssignmentId(studentName); // <-- ADD THIS
    Map<String, ClassOrInterfaceDeclaration> classMap = entry.getValue();

    System.out.println("\n=== Running detections for " + studentName + " (Assignment: " + assignmentId + ") ===");

    // Basic detections on each class
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
    detectEnumTypeChecks(clazz, allEnumNames, studentName);
    
    if (hasTypeField(clazz)) {
        detectTypeCheckingInMethods(clazz, studentName);
    }
    
    //
    // Check for parent class before calling detectLSPViolations
    if (!clazz.getExtendedTypes().isEmpty()) {
        String parentName = clazz.getExtendedTypes(0).getNameAsString();
        ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
        
        if (parentClass != null) {
            detectLSPViolations(clazz, parentClass, assignmentId);
        }
    }
    
    detectEmptyOverrides(clazz, assignmentId, classMap);
}

    // Inheritance-based detections
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (!clazz.getExtendedTypes().isEmpty()) {
            String parentName = clazz.getExtendedTypes(0).getNameAsString();
            ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
            
            if (parentClass != null) {
                detectRedundantOverrides(clazz, parentClass, studentName, classMap);
                // NEW: Detect LSP violations
                detectLSPViolations(clazz, parentClass, assignmentId); // <-- PASS assignmentId
            }
        }
        
        // NEW: Check for empty overrides (potential LSP violations)
        detectEmptyOverrides(clazz, assignmentId, classMap);; // <-- PASS assignmentId
    }

    // Cross-class detections
    detectMissingInheritance(classMap, studentName);
    detectRedundantSuperclass(classMap, studentName);
}

        String outputFile = "oop_antipattern_all.csv";
        writeCsv(outputFile);
        
        // NEW: Write LLM candidates JSON
        writeLLMCandidates("llm_candidates.json");
        
        System.out.println("\nAnalysis complete! Results saved to: " + outputFile);
        System.out.println("LLM candidates saved to: llm_candidates.json");
    }

    private static String extractAssignmentId(String studentName) {
    // Extract assignment ID from student directory name
    // Example: "assignment-1-109" or "109-1" etc.
    if (studentName.contains("assignment")) {
        return studentName;
    }
    
    // Try to find patterns
    String[] parts = studentName.split("[-_]");
    if (parts.length >= 2) {
        // Check if it looks like "109-1" format
        try {
            Integer.parseInt(parts[0]);
            return studentName; // Return as-is if it starts with a number
        } catch (NumberFormatException e) {
            // Not a number, try to construct assignment ID
            if (parts.length >= 3) {
                return "assignment-" + parts[parts.length-2] + "-" + parts[parts.length-1];
            }
        }
    }
    
    // Default: return student name
    return studentName;
}

    // =============== NEW: LSP VIOLATION DETECTION ===============
    
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
        
        // SKIP if parent is abstract - no LSP check needed for implementations
        if (parentMethod.isAbstract()) {
            continue; // Child is implementing, not overriding
        }
        
        // Only check LSP for concrete method overrides
        // ... rest of your LSP checks ...
    }
}

private static void detectEmptyOverrides(ClassOrInterfaceDeclaration childClass,
                                        String assignmentId,
                                        Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    // Check if class has a parent
    if (childClass.getExtendedTypes().isEmpty()) {
        return; // No parent to override from
    }
    
    String parentName = childClass.getExtendedTypes(0).getNameAsString();
    ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
    
    if (parentClass == null) {
        return; // Parent not in our class map
    }
    
    // Get all parent method signatures
    Map<String, MethodDeclaration> parentMethods = getMethodSignatures(parentClass);
    
    for (MethodDeclaration childMethod : childClass.getMethods()) {
        String sig = childMethod.getSignature().asString();
        MethodDeclaration parentMethod = parentMethods.get(sig);
        
        if (parentMethod == null) {
            continue; // Not an override
        }
        
        // SKIP if parent method is ABSTRACT - child MUST implement!
        if (parentMethod.isAbstract()) {
            continue; // This is VALID - implementing abstract method
        }
        
        // Check if child method has a body
        Optional<BlockStmt> childBody = childMethod.getBody();
        if (childBody.isEmpty()) {
            continue; // Abstract method in child
        }
        
        // Check if child body is empty
        boolean childIsEmpty = isEmptyBody(childBody.get());
        if (!childIsEmpty) {
            continue; // Child has implementation
        }
        
        // Check if parent has a body
        Optional<BlockStmt> parentBody = parentMethod.getBody();
        if (parentBody.isEmpty()) {
            // Parent has no body (interface default method?) - send to LLM
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "EmptyOverrideInterface",
                Map.of(
                    "details", "Empty override of interface/default method",
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentType", "interface/default",
                    "astVerdict", "UNSURE_NEEDS_LLM"
                ));
            continue;
        }
        
        // Check if parent body is also empty
        boolean parentIsEmpty = isEmptyBody(parentBody.get());
        if (parentIsEmpty) {
            // Both empty - usually fine, but let LLM check for edge cases
            String parentBodyStr = parentBody.get().toString();
            boolean parentHasComments = hasMeaningfulComments(parentBodyStr);
            
            if (parentHasComments) {
                // Parent has comments suggesting expected behavior
                addLLMCandidate(assignmentId, childClass.getNameAsString(),
                    childMethod.getNameAsString(), "EmptyOverrideWithComments",
                    Map.of(
                        "details", "Empty override of documented empty method",
                        "parentSignature", parentMethod.getDeclarationAsString(),
                        "childSignature", childMethod.getDeclarationAsString(),
                        "parentBody", parentBodyStr,
                        "parentHasComments", "true",
                        "astVerdict", "MAYBE_NEEDS_LLM"
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
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "DefectiveEmptyOverride",
                Map.of(
                    "details", "Empty override disables parent's logic",
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentBodyPreview", getBodyPreview(parentBodyStr),
                    "parentLogicComplexity", assessComplexity(parentBody.get()),
                    "astVerdict", "CLEAR_VIOLATION"
                ));
        } else {
            // Parent body exists but is trivial (e.g., just returns null/0)
            // Send to LLM to decide if this violates contract
            addLLMCandidate(assignmentId, childClass.getNameAsString(),
                childMethod.getNameAsString(), "AmbiguousEmptyOverride",
                Map.of(
                    "details", "Empty override of trivial parent method",
                    "parentSignature", parentMethod.getDeclarationAsString(),
                    "childSignature", childMethod.getDeclarationAsString(),
                    "parentBody", parentBodyStr,
                    "parentIsTrivial", "true",
                    "astVerdict", "UNSURE_NEEDS_LLM"
                ));
        }
    }
}

// Helper methods
private static boolean hasRealLogic(BlockStmt body) {
    String normalized = body.toString()
        .replaceAll("//.*|/\\*(.|\\R)*?\\*/", "")
        .replaceAll("\\s+", "")
        .replaceAll("[{};]", "");
    
    // Check for actual statements (not just empty or trivial returns)
    return !normalized.isEmpty() && 
           !normalized.equals("return") &&
           !normalized.equals("returnnull") &&
           !normalized.equals("return0") &&
           !normalized.equals("returnfalse") &&
           !normalized.equals("returntrue") &&
           !normalized.startsWith("returnthis") &&
           normalized.length() > 10; // Arbitrary threshold for "real logic"
}

private static boolean hasMeaningfulComments(String body) {
    // Check if body has comments that might indicate expected behavior
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

// Add this helper method
private static MethodDeclaration findParentMethod(MethodDeclaration childMethod,
                                                 ClassOrInterfaceDeclaration parentClass) {
    String childName = childMethod.getNameAsString();
    List<Parameter> childParams = childMethod.getParameters();
    
    // Look for method with same name and parameters in parent
    for (MethodDeclaration parentMethod : parentClass.getMethods()) {
        if (!parentMethod.getNameAsString().equals(childName)) {
            continue;
        }
        
        // Check if parameters match
        if (parentMethod.getParameters().size() != childParams.size()) {
            continue;
        }
        
        boolean paramsMatch = true;
        for (int i = 0; i < childParams.size(); i++) {
            String childParamType = childParams.get(i).getType().asString();
            String parentParamType = parentMethod.getParameter(i).getType().asString();
            
            if (!childParamType.equals(parentParamType)) {
                paramsMatch = false;
                break;
            }
        }
        
        if (paramsMatch) {
            return parentMethod;
        }
    }
    
    return null;
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
                        System.out.printf("Improper polymorphism in %s.%s(): type.equals(...) check%n",
                                clazz.getNameAsString(), method.getNameAsString());

                        csvRows.add(new String[]{
                                studentName,
                                clazz.getNameAsString(),
                                method.getNameAsString(),
                                "Improper Polymorphism",
                                "HIGH",
                                "type.equals(...) check"
                        });
                    }
                    
                    if (cond instanceof InstanceOfExpr) {
                        System.out.printf("Type checking in %s.%s(): uses instanceof%n",
                                clazz.getNameAsString(), method.getNameAsString());

                        csvRows.add(new String[]{
                                studentName,
                                clazz.getNameAsString(),
                                method.getNameAsString(),
                                "Type Checking",
                                "MEDIUM",
                                "Uses instanceof instead of polymorphism"
                        });
                    }
                }
            }
            
            methodBody.findAll(BinaryExpr.class).forEach(binaryExpr -> {
                if (binaryExpr.getOperator() == BinaryExpr.Operator.EQUALS ||
                    binaryExpr.getOperator() == BinaryExpr.Operator.NOT_EQUALS) {
                    
                    String expr = binaryExpr.toString();
                    if (expr.contains(".getClass()") || expr.contains(".class")) {
                        System.out.printf("Type checking in %s.%s(): getClass() or .class comparison%n",
                                clazz.getNameAsString(), method.getNameAsString());

                        csvRows.add(new String[]{
                                studentName,
                                clazz.getNameAsString(),
                                method.getNameAsString(),
                                "Type Checking",
                                "MEDIUM",
                                "Uses getClass() or .class comparison instead of polymorphism"
                        });
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

    private static void detectEnumTypeChecks(ClassOrInterfaceDeclaration clazz, Set<String> allEnumNames, 
                                            String studentName) {
        for (FieldDeclaration field : clazz.getFields()) {
            String fieldName = field.getVariables().get(0).getNameAsString();
            String fieldType = field.getElementType().asString();

            if (!allEnumNames.contains(fieldType)) continue;

            for (MethodDeclaration method : clazz.getMethods()) {
                Optional<BlockStmt> body = method.getBody();
                if (!body.isPresent()) continue;

                body.get().findAll(IfStmt.class).forEach(ifStmt -> {
                    Expression cond = ifStmt.getCondition();
                    if (isEnumComparison(cond, fieldName)) {
                        System.out.printf("Enum misuse in %s.%s(): enum comparison%n",
                                clazz.getNameAsString(), method.getNameAsString());

                        csvRows.add(new String[]{
                                studentName,
                                clazz.getNameAsString(),
                                method.getNameAsString(),
                                "Enum Misuse",
                                "MEDIUM",
                                "Enum comparison used"
                        });
                    }
                });

                body.get().findAll(SwitchStmt.class).forEach(switchStmt -> {
                    Expression selector = switchStmt.getSelector();
                    if (selector.isNameExpr() && selector.asNameExpr().getNameAsString().equals(fieldName)) {
                        String severity = getSwitchSeverity(switchStmt);
                        String details = getSwitchIssueDetails(switchStmt, severity);
                        
                        csvRows.add(new String[]{
                            studentName,
                            clazz.getNameAsString(),
                            method.getNameAsString(),
                            "Enum Usage",
                            severity,
                            details
                        });
                    }
                });
            }
        }
    }

    private static boolean isEnumComparison(Expression expr, String enumFieldName) {
        if (!(expr instanceof BinaryExpr)) return false;
        BinaryExpr be = (BinaryExpr) expr;

        if (be.getOperator() != BinaryExpr.Operator.EQUALS &&
            be.getOperator() != BinaryExpr.Operator.NOT_EQUALS) return false;

        Expression left = be.getLeft();
        Expression right = be.getRight();

        return (isFieldName(left, enumFieldName) && right.isFieldAccessExpr()) ||
               (isFieldName(right, enumFieldName) && left.isFieldAccessExpr());
    }

    private static boolean isFieldName(Expression expr, String name) {
        return expr.isNameExpr() && expr.asNameExpr().getNameAsString().equals(name);
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

    private static String getSwitchIssueDetails(SwitchStmt switchStmt, String severity) {
        switch (severity) {
            case "HIGH":
                return "Switch contains significant execution logic (>5 lines per case)";
            case "MEDIUM":
                return "Switch mixes object creation with some execution logic";
            case "LOW":
                return "Switch is factory pattern but could be improved";
            default:
                return "Switch on enum detected";
        }
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
                        System.out.printf("Redundant override in %s.%s(): identical to parent%n",
                                child.getNameAsString(), childMethod.getSignature());

                        csvRows.add(new String[]{
                                studentName,
                                child.getNameAsString(),
                                childMethod.getNameAsString(),
                                "Redundant Override",
                                "MEDIUM",
                                "Identical to parent method"
                        });
                    }
                }
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
                
                if (OBJECT_METHOD_NAMES.contains(method.getNameAsString())) continue;

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

            csvRows.add(new String[]{
                    studentName,
                    String.join(";", classes),
                    entry.getKey(),
                    "Missing Inheritance",
                    "HIGH",
                    "Classes define same method but do not share superclass or interface"
            });

            System.out.printf("Missing inheritance: %s | %s -> %s%n",
                    studentName, classes, entry.getKey());
        }
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