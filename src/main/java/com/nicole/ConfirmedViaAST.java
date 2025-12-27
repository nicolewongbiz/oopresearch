package com.nicole;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.comments.Comment;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ConfirmedViaAST {

    private static List<String[]> csvRows = new ArrayList<>();

    private static final Set<String> FRAMEWORK_METHOD_NAMES = Set.of("setUp", "tearDown");
    private static final Set<String> OBJECT_METHOD_NAMES = Set.of("equals", "hashCode", "toString");

    public static void main(String[] args) throws Exception {
        File submissionsDir = new File("C:\\Users\\GGPC\\Downloads\\assignment-2022-3\\assignment-3_output");
        if (!submissionsDir.exists()) {
            System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
            return;
        }

        // CSV header
        csvRows.add(new String[]{"Student", "Class", "Method", "IssueType", "Details", "Source"});

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
                } catch (Exception e) {
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
                }
            }
        }

        // Parse all files
        List<CompilationUnit> units = new ArrayList<>();
        JavaParser parser = new JavaParser();
        for (File f : javaFiles) {
            ParseResult<CompilationUnit> result = parser.parse(f);
            if (result.isSuccessful() && result.getResult().isPresent()) {
                CompilationUnit cu = result.getResult().get();
                cu.setStorage(f.toPath());
                units.add(cu);
            }
        }

        // Group classes by student
        Map<String, Map<String, ClassOrInterfaceDeclaration>> groupedClassMaps = new HashMap<>();
        for (CompilationUnit cu : units) {
            if (!cu.getStorage().isPresent()) continue;
            String keyPath = cu.getStorage().get().getPath().toAbsolutePath().toString();
            String studentName = fileToStudent.get(keyPath);
            if (studentName == null) continue;

            groupedClassMaps.computeIfAbsent(studentName, k -> new HashMap<>());
            for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                groupedClassMaps.get(studentName).put(clazz.getNameAsString(), clazz);
            }
        }

        // Perform AST-only detections
        for (Map.Entry<String, Map<String, ClassOrInterfaceDeclaration>> entry : groupedClassMaps.entrySet()) {
            String studentName = entry.getKey();
            Map<String, ClassOrInterfaceDeclaration> classMap = entry.getValue();

            for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
                if (hasTypeField(clazz)) detectTypeCheckingInMethodsConservative(clazz, studentName);

                // Redundant overrides (AST-only)
                if (!clazz.getExtendedTypes().isEmpty()) {
                    String parentName = clazz.getExtendedTypes(0).getNameAsString();
                    ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
                    if (parentClass != null) {
                        detectRedundantOverridesConservative(clazz, parentClass, studentName);
                    }
                }
            }
        }

        writeCsv("oop_antipattern_ast_only.csv");
        
        // Print statistics
        printStatistics();
    }

    // ----------------

    private static void detectRedundantOverridesConservative(ClassOrInterfaceDeclaration child,
                                                         ClassOrInterfaceDeclaration parent,
                                                         String studentName) {

        Map<String, MethodDeclaration> parentMethods = new HashMap<>();
        for (MethodDeclaration pm : parent.getMethods()) {
            parentMethods.put(pm.getSignature().asString(), pm);
        }

        // List to collect redundant methods
        List<String> redundantMethods = new ArrayList<>();

        for (MethodDeclaration childMethod : child.getMethods()) {
            String sig = childMethod.getSignature().asString();
            if (!parentMethods.containsKey(sig)) continue;

            MethodDeclaration parentMethod = parentMethods.get(sig);

            if (parentMethod.getBody().isEmpty() || childMethod.getBody().isEmpty()) {
                continue;
            }

            BlockStmt parentBody = parentMethod.getBody().get();
            BlockStmt childBody = childMethod.getBody().get();

            removeAllComments(parentBody);
            removeAllComments(childBody);

            String parentStr = normalizeCode(parentBody.toString());
            String childStr = normalizeCode(childBody.toString());

            if (!parentStr.equals(childStr)) {
                continue;
            }

            // 🚨 NEW: semantic safety check (field shadowing)
            if (referencesShadowedField(childMethod, child, parent)) {
                continue;
            }

            if (!OBJECT_METHOD_NAMES.contains(childMethod.getNameAsString())
                    && !FRAMEWORK_METHOD_NAMES.contains(childMethod.getNameAsString())) {
                
                redundantMethods.add(childMethod.getNameAsString());
            }
        }
        
        // Add grouped or individual entries
        if (!redundantMethods.isEmpty()) {
            // Always use the same issue type for consistency
            String issueType = "Redundant Override";
            
            if (redundantMethods.size() == 1) {
                // Single method
                csvRows.add(new String[]{
                    studentName,
                    child.getNameAsString(),
                    redundantMethods.get(0),
                    issueType,
                    "Identical to parent method with no semantic difference",
                    "AST-detected"
                });
            } else {
                // Multiple methods - group them
                String methodsStr = String.join("; ", redundantMethods);
                csvRows.add(new String[]{
                    studentName,
                    child.getNameAsString(),
                    methodsStr,
                    issueType,  // Same issue type, not "Group"
                    redundantMethods.size() + " methods identical to parent: " + methodsStr,
                    "AST-detected"
                });
            }
        }
    }

    private static boolean referencesShadowedField(MethodDeclaration method,
                                                ClassOrInterfaceDeclaration child,
                                                ClassOrInterfaceDeclaration parent) {

        // Fields declared in child
        Set<String> childFields = child.getFields().stream()
                .flatMap(f -> f.getVariables().stream())
                .map(v -> v.getNameAsString())
                .collect(Collectors.toSet());

        // Fields declared in parent
        Set<String> parentFields = parent.getFields().stream()
                .flatMap(f -> f.getVariables().stream())
                .map(v -> v.getNameAsString())
                .collect(Collectors.toSet());

        // Shadowed = same name exists in both
        childFields.retainAll(parentFields);
        if (childFields.isEmpty()) return false;

        // Does method reference any of those names?
        return method.findAll(NameExpr.class).stream()
                .anyMatch(n -> childFields.contains(n.getNameAsString()));
    }
    
    private static void detectTypeCheckingInMethodsConservative(ClassOrInterfaceDeclaration clazz, String studentName) {
        // Group type checking methods in the same class
        List<String> typeCheckingMethods = new ArrayList<>();
        
        for (MethodDeclaration method : clazz.getMethods()) {
            Optional<BlockStmt> body = method.getBody();
            if (body.isEmpty()) continue;
            
            boolean hasTypeCheck = false;
            for (Statement stmt : body.get().getStatements()) {
                if (stmt.isIfStmt()) {
                    IfStmt ifStmt = stmt.asIfStmt();
                    Expression cond = ifStmt.getCondition();
                    if (isTypeEqualsCheck(cond)) {
                        hasTypeCheck = true;
                        break;
                    }
                }
            }
            
            if (hasTypeCheck) {
                typeCheckingMethods.add(method.getNameAsString());
            }
        }
        
        // Add grouped or individual entries
        if (!typeCheckingMethods.isEmpty()) {
            // Always use the same issue type for consistency
            String issueType = "Improper Polymorphism";
            
            if (typeCheckingMethods.size() == 1) {
                csvRows.add(new String[]{
                    studentName,
                    clazz.getNameAsString(),
                    typeCheckingMethods.get(0),
                    issueType,
                    "type.equals(...) check",
                    "AST-detected"
                });
            } else {
                // Multiple methods with type checking
                String methodsStr = String.join("; ", typeCheckingMethods);
                csvRows.add(new String[]{
                    studentName,
                    clazz.getNameAsString(),
                    methodsStr,
                    issueType,  // Same issue type, not "Group"
                    typeCheckingMethods.size() + " methods use type.equals(...) checks: " + methodsStr,
                    "AST-detected"
                });
            }
        }
    }

    private static boolean isTypeEqualsCheck(Expression expr) {
        if (!(expr instanceof MethodCallExpr)) return false;
        MethodCallExpr mcall = (MethodCallExpr) expr;
        if (!mcall.getNameAsString().equals("equals")) return false;
        if (mcall.getScope().isEmpty()) return false;
        Expression scope = mcall.getScope().get();
        return scope.isNameExpr() && scope.asNameExpr().getNameAsString().equals("type");
    }

    private static boolean hasTypeField(ClassOrInterfaceDeclaration clazz) {
        return clazz.getFields().stream()
                .flatMap(f -> f.getVariables().stream())
                .anyMatch(v -> v.getNameAsString().equals("type"));
    }

    private static void removeAllComments(Node node) {
        node.getAllContainedComments().forEach(Comment::remove);
    }

    private static String normalizeCode(String code) {
        return code.replaceAll("//.*|/\\*(.|\\R)*?\\*/", "")
                   .replaceAll("\\s+", "")
                   .trim();
    }

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
    
    private static void printStatistics() {
        System.out.println("\n=== AST DETECTION STATISTICS ===");
        System.out.println("Total issues detected: " + (csvRows.size() - 1)); // -1 for header
        
        // Count by issue type (skip header)
        Map<String, Integer> issueTypeCounts = new HashMap<>();
        for (int i = 1; i < csvRows.size(); i++) {
            String[] row = csvRows.get(i);
            if (row.length > 3) {
                String issueType = row[3];
                issueTypeCounts.put(issueType, issueTypeCounts.getOrDefault(issueType, 0) + 1);
            }
        }
        
        System.out.println("\nBreakdown by issue type:");
        for (Map.Entry<String, Integer> entry : issueTypeCounts.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue());
        }
        
        // Also print grouped vs individual statistics
        System.out.println("\nDetails:");
        int individualIssues = 0;
        int groupedIssues = 0;
        int totalMethodsInGroups = 0;
        
        for (int i = 1; i < csvRows.size(); i++) {
            String[] row = csvRows.get(i);
            if (row.length > 2) {
                String methodCell = row[2];
                if (methodCell.contains(";")) {
                    groupedIssues++;
                    totalMethodsInGroups += methodCell.split(";").length;
                } else {
                    individualIssues++;
                }
            }
        }
        
        System.out.println("  Individual method issues: " + individualIssues);
        System.out.println("  Grouped issues (multiple methods): " + groupedIssues);
        System.out.println("  Total methods in grouped issues: " + totalMethodsInGroups);
        System.out.println("  Average methods per grouped issue: " + 
            (groupedIssues > 0 ? String.format("%.2f", (double)totalMethodsInGroups / groupedIssues) : "0"));
    }
}