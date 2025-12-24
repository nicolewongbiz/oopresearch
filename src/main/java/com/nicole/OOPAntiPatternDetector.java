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
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;



public class OOPAntiPatternDetector {

    private static List<String[]> csvRows = new ArrayList<>();


    private static final Set<String> FRAMEWORK_METHOD_NAMES =
        Set.of("setUp", "tearDown");


    private static final Set<String> OBJECT_METHOD_NAMES =
        Set.of("equals", "hashCode", "toString");


    public static void main(String[] args) throws Exception {
        File submissionsDir = new File("C:\\Users\\GGPC\\Downloads\\assignment-1\\assignment-1\\assignment-1-repos");
        if (!submissionsDir.exists()) {
            System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
            return;
        }

    // CSV header
    csvRows.add(new String[]{"Student", "Class", "Method", "IssueType", "Severity", "Details"});

    // Iterate all java files inside student folders (include nested)
    List<File> javaFiles = new ArrayList<>();
    Map<String, String> fileToStudent = new HashMap<>(); // key = absolute filepath, value = student name

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

    System.out.println("Parsed classes (grouped):");
    for (Map.Entry<String, Map<String, ClassOrInterfaceDeclaration>> entry : groupedClassMaps.entrySet()) {
        System.out.println("Student: " + entry.getKey());
        for (String className : entry.getValue().keySet()) {
            System.out.println(" - " + className);
        }
    }

    // Perform detections per student
    for (Map.Entry<String, Map<String, ClassOrInterfaceDeclaration>> entry : groupedClassMaps.entrySet()) {
        String studentName = entry.getKey();
        Map<String, ClassOrInterfaceDeclaration> classMap = entry.getValue();

        System.out.println("\n=== Running detections for " + studentName + " ===");

        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            detectEnumTypeChecks(clazz, allEnumNames, studentName, "N/A");
            if (hasTypeField(clazz)) {
                detectTypeCheckingInMethods(clazz, studentName, "N/A");
            }
        }

        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            if (!clazz.getExtendedTypes().isEmpty()) {
                String parentName = clazz.getExtendedTypes(0).getNameAsString();
                ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
                
                if (parentClass != null) {
                    detectRedundantOverrides(clazz, parentClass, studentName, "N/A", classMap);
                }
            }
        }

        detectMissingInheritance(classMap, studentName, "N/A");
        detectRedundantSuperclass(classMap, studentName, "N/A");
    }

    writeCsv("oop_antipattern_all.csv");
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
        System.out.println("CSV results written to " + fileName);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

private static String getExampleFolder(Path studentDirPath, Path filePath) {
    try {
        Path studentBase = studentDirPath.toRealPath();
        Path current = filePath.getParent().toRealPath();

        while (current != null && current.startsWith(studentBase)) {
            Path name = current.getFileName();
            if (name != null) {
                String s = name.toString().toLowerCase().trim();
                if (s.startsWith("assignment-1")) {
                    return name.toString(); // return original folder name
                }
            }
            current = current.getParent();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
    return "NoExample";
}

private static boolean pathHasExampleDir(Path filePath, Path studentDirPath) {
    try {
        Path current = filePath.getParent().toRealPath();
        Path studentBase = studentDirPath.toRealPath();

        while (current != null && current.startsWith(studentBase)) {
            Path name = current.getFileName();
            if (name != null) {
                String s = name.toString().toLowerCase();
                if (s.startsWith("assignment-1")) return true;
            }
            current = current.getParent();
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
    return false;
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

private static void detectTypeCheckingInMethods(ClassOrInterfaceDeclaration clazz, String studentName, String exampleFolder) {
    for (MethodDeclaration method : clazz.getMethods()) {
        Optional<BlockStmt> body = method.getBody();
        if (body.isEmpty()) continue;

        for (Statement stmt : body.get().getStatements()) {
            if (stmt.isIfStmt()) {
                IfStmt ifStmt = stmt.asIfStmt();
                Expression cond = ifStmt.getCondition();

                if (isTypeEqualsCheck(cond)) {
                    System.out.printf("Improper polymorphism detected in %s.%s(): uses type.equals(...) check%n",
                            clazz.getNameAsString(), method.getNameAsString());

                    csvRows.add(new String[]{
                            studentName,
                            clazz.getNameAsString(),
                            method.getNameAsString(),
                            "Improper Polymorphism",
                            "type.equals(...) check"
                    });
                }
            }
        }
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


private static void detectEnumTypeChecks(ClassOrInterfaceDeclaration clazz, Set<String> allEnumNames, String studentName, String exampleFolder) {
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
                    System.out.printf("Enum misuse detected in %s.%s(): enum comparison%n",
                            clazz.getNameAsString(),
                            method.getNameAsString());

                    csvRows.add(new String[]{
                            studentName,
                            clazz.getNameAsString(),
                            method.getNameAsString(),
                            "Enum Misuse",
                            "Enum comparison used"
                    });
                }
            });

        body.get().findAll(SwitchStmt.class).forEach(switchStmt -> {
    Expression selector = switchStmt.getSelector();
    if (selector.isNameExpr() && selector.asNameExpr().getNameAsString().equals(fieldName)) {
        
        // Categorize the switch
        String severity = getSwitchSeverity(switchStmt);
        String details = getSwitchIssueDetails(switchStmt, severity);
        
       
        // ALWAYS report enum switch usage (superset guarantee)
        csvRows.add(new String[]{
            studentName,
            clazz.getNameAsString(),
            method.getNameAsString(),
            "Enum Usage",
            severity,
            details
        });

        // LOW severity (good factories) - don't flag
    }
});
        }
    }
}

// Testing: Strict check for pure factory pattern
// private static boolean isPureFactorySwitch(SwitchStmt switchStmt) {
//     List<SwitchEntry> entries = switchStmt.getEntries();
    
//     for (SwitchEntry entry : entries) {
//         if (entry.getLabels().isEmpty()) continue;
        
//         boolean hasNew = false;
//         for (Statement stmt : entry.getStatements()) {
//             String stmtStr = stmt.toString().toLowerCase();
            
//             // Must have object creation
//             if (stmtStr.contains("new ")) {
//                 hasNew = true;
//             }
            
//             // Must not have any bad patterns
//             if (stmtStr.contains(".execute") || 
//                 stmtStr.contains(".process") ||
//                 stmtStr.contains(".play") ||
//                 stmtStr.contains(".showwinner") ||
//                 stmtStr.contains(".aimove") ||
//                 stmtStr.contains("messagecli") ||
//                 stmtStr.contains("++") ||
//                 stmtStr.contains("--") ||
//                 stmtStr.contains("winrounds") ||
//                 stmtStr.contains("round++")) {
//                 return false;
//             }
//         }
        
//         // Each case must create an object
//         if (!hasNew) return false;
//     }
    
//     return true;
// }

// private static boolean isDefinitelyBadSwitch(SwitchStmt switchStmt) {
//     List<SwitchEntry> entries = switchStmt.getEntries();
    
//     // Testing: Check for obvious bad patterns
//     for (SwitchEntry entry : entries) {
//         for (Statement stmt : entry.getStatements()) {
//             String stmtStr = stmt.toString().toLowerCase();
            
//             // list of bad patterns
//             if (stmtStr.contains("messagecli") ||
//                 stmtStr.contains("humanwinrounds") ||
//                 stmtStr.contains("aiwinrounds") ||
//                 stmtStr.contains("round++") ||
//                 stmtStr.contains("fingerscount") ||
//                 stmtStr.contains("showwinner") ||
//                 stmtStr.contains("aimove") ||
//                 stmtStr.contains(".play") ||
//                 stmtStr.contains("utils.getrandomnumber") ||
//                 stmtStr.contains("++") ||
//                 stmtStr.contains("--") ||
//                 stmtStr.contains("fingerhistory") ||
//                 stmtStr.contains("fingershuman.add") ||
//                 stmtStr.contains("avgfingers") ||
//                 stmtStr.contains("while(") ||
//                 stmtStr.contains("if(")) {
//                 return true;
//             }
//         }
//     }
    
//     // Check line count
//     int totalLines = 0;
//     int totalCases = 0;
    
//     for (SwitchEntry entry : entries) {
//         if (entry.getLabels().isEmpty()) continue;
//         totalCases++;
        
//         for (Statement stmt : entry.getStatements()) {
//             totalLines += stmt.toString().split("\n").length;
//         }
//     }
    
//     if (totalCases == 0) return false;
    
//     double avgLines = (double) totalLines / totalCases;
    
//     // Test thresholds
//     if (avgLines >= 4.0) return true;  // Changed from 5.0 to 4.0
    
//     return false;
// }

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

// Check for bad patterns in switch
private static boolean hasBadPatternsInSwitch(SwitchStmt switchStmt) {
    String switchText = switchStmt.toString().toLowerCase();
    
    // bad patterns (execution in switch)
    if (switchText.contains("utils.getrandomnumber") ||
        switchText.contains("round++") ||
        switchText.contains("++") ||
        switchText.contains("--") ||
        switchText.contains("fingershuman.add") ||
        switchText.contains("avgfingers") ||
        switchText.contains("sumfingers") ||
        switchText.contains("while(") ||
        switchText.contains("if(")) {
        return true;
    }
    
    // Check for MessageCli
    if (switchText.contains("messagecli")) {
        // Count how many MessageCli calls are in REGULAR cases (not default)
        List<SwitchEntry> entries = switchStmt.getEntries();
        int messageCliInRegularCases = 0;
        
        for (SwitchEntry entry : entries) {
            // Skip default case (labels empty)
            if (entry.getLabels().isEmpty()) continue;
            
            for (Statement stmt : entry.getStatements()) {
                if (stmt.toString().toLowerCase().contains("messagecli")) {
                    messageCliInRegularCases++;
                }
            }
        }
        
        // If MessageCli is in regular cases, it's bad
        return messageCliInRegularCases > 0;
    }
    
    return false;
}

// Simple check for factory pattern (1-2 lines per case, just object creation)
private static boolean isSimpleFactorySwitch(SwitchStmt switchStmt) {
    List<SwitchEntry> entries = switchStmt.getEntries();
    
    for (SwitchEntry entry : entries) {
        if (entry.getLabels().isEmpty()) continue;
        
        List<Statement> statements = entry.getStatements();
        
        // Factory should have 1-3 statements max per case
        if (statements.size() > 3) return false;
        
        // Check statements
        for (Statement stmt : statements) {
            String stmtStr = stmt.toString().toLowerCase();
            
            // Should only have object creation or assignment
            if (!stmtStr.contains("new ") && 
                !stmtStr.contains("= ") && 
                !stmtStr.contains("return ")) {
                return false;
            }
            
            // Should not have execution
            if (stmtStr.contains("(") && !stmtStr.contains("new ") && 
                !stmtStr.contains("return ")) {
                // Has method call that's not object creation
                return false;
            }
        }
    }
    
    return true;
}

// private static boolean isLikelyBadSwitch(SwitchStmt switchStmt) {
//     List<SwitchEntry> entries = switchStmt.getEntries();
    
//     int totalLines = 0;
//     int totalCases = 0;
    
//     for (SwitchEntry entry : entries) {
//         if (entry.getLabels().isEmpty()) continue;
//         totalCases++;
        
//         for (Statement stmt : entry.getStatements()) {
//             totalLines += stmt.toString().split("\n").length;
//         }
//     }
    
//     if (totalCases == 0) return false;
    
//     double avgLinesPerCase = (double) totalLines / totalCases;
    
//     // Lower thresholds
//     if (avgLinesPerCase >= 3.0) return true;        // Changed from 5.0
//     if (totalCases >= 3 && avgLinesPerCase >= 2.0) return true;  // Changed from 3.0
    
//     return hasCodeDuplication(entries);
// }

// Testing: Check for code duplication across switch cases
private static boolean hasCodeDuplication(List<SwitchEntry> entries) {
    if (entries.size() < 2) return false;
    
    // Extract method call signatures from each case
    List<Set<String>> caseMethodCalls = new ArrayList<>();
    
    for (SwitchEntry entry : entries) {
        if (entry.getLabels().isEmpty()) continue;
        
        Set<String> methodCalls = new HashSet<>();
        for (Statement stmt : entry.getStatements()) {
            // Find method calls
            stmt.findAll(MethodCallExpr.class).forEach(mcall -> {
                String call = mcall.getNameAsString().toLowerCase();
                // Ignore common calls like "add", "get", "set"
                if (!call.equals("add") && !call.equals("get") && 
                    !call.equals("set") && !call.equals("equals")) {
                    methodCalls.add(call);
                }
            });
        }
        caseMethodCalls.add(methodCalls);
    }
    
    // Check if cases have similar method calls
    if (caseMethodCalls.size() < 2) return false;
    
    Set<String> firstMethods = caseMethodCalls.get(0);
    for (int i = 1; i < caseMethodCalls.size(); i++) {
        Set<String> currentMethods = caseMethodCalls.get(i);
        
        // If cases share 2+ unique method calls, likely duplicated logic
        Set<String> intersection = new HashSet<>(firstMethods);
        intersection.retainAll(currentMethods);
        
        if (intersection.size() >= 2) {
            return true; // Duplicated method calls
        }
    }
    
    return false;
}

// Testing: Categorize switch severity
private static String getSwitchSeverity(SwitchStmt switchStmt) {
    List<SwitchEntry> entries = switchStmt.getEntries();
    
    int totalLines = 0;
    int totalCases = 0;
    int casesWithExecution = 0;
    int casesWithObjectCreation = 0;
    
    for (SwitchEntry entry : entries) {
        if (entry.getLabels().isEmpty()) continue; // Skip default
        
        totalCases++;
        boolean hasExecution = false;
        boolean hasObjectCreation = false;
        
        for (Statement stmt : entry.getStatements()) {
            String stmtStr = stmt.toString().toLowerCase();
            totalLines += stmtStr.split("\n").length;
            
            // Check for execution patterns
            if (stmtStr.contains("utils.getrandomnumber") ||
                stmtStr.contains("round++") ||
                stmtStr.contains("++") ||
                stmtStr.contains("--") ||
                stmtStr.contains(".add(") ||
                stmtStr.contains("if(") ||
                stmtStr.contains("while(") ||
                stmtStr.contains("messagecli")) {
                hasExecution = true;
            }
            
            // Check for object creation
            if (stmtStr.contains("new ") || stmtStr.contains("factory")) {
                hasObjectCreation = true;
            }
        }
        
        if (hasExecution) casesWithExecution++;
        if (hasObjectCreation) casesWithObjectCreation++;
    }
    
    if (totalCases == 0) return "LOW";
    
    double avgLines = (double) totalLines / totalCases;

    // Testing: CATEGORIZATION LOGIC:

    // 1. HIGH: Mostly execution, long cases
    if (casesWithExecution > totalCases * 0.7 || avgLines >= 5.0) {
        return "HIGH";
    }
    
    // 2. MEDIUM: Mix of execution and object creation
    if (casesWithExecution > 0 && casesWithObjectCreation > 0) {
        return "MEDIUM";
    }
    
    // 3. LOW: Pure factory (mostly object creation, short)
    if (casesWithObjectCreation >= totalCases * 0.7 && avgLines <= 3.0) {
        return "LOW";
    }
    
    // Default to MEDIUM for unclear cases
    return "MEDIUM";
}

// Testing: Get detailed reason
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

// private static boolean isObjectCreationSwitch(List<SwitchEntry> entries) {
//     if (entries.isEmpty()) return false;
    
//     int totalValidCases = 0;
    
//     for (SwitchEntry entry : entries) {
//         if (entry.getLabels().isEmpty()) continue;
//         totalValidCases++;
        
//         List<Statement> statements = entry.getStatements();
//         if (statements.isEmpty()) continue;
        
//         for (Statement stmt : statements) {
//             String stmtStr = stmt.toString().toLowerCase();
            
//             // If ANY case has bad patterns, it's not a pure factory
//             if (stmtStr.contains("messagecli") ||
//                 stmtStr.contains("humanwinrounds") ||
//                 stmtStr.contains("aiwinrounds") ||
//                 stmtStr.contains("round++") ||
//                 stmtStr.contains("++") ||
//                 stmtStr.contains("--") ||
//                 stmtStr.contains(".play(") ||
//                 stmtStr.contains("utils.getrandomnumber")) {
//                 return false;
//             }
//         }
//     }
    
//     // If we got here, no bad patterns were found
//     return totalValidCases > 0;
// }

// Testing: Check for execution patterns inside switch cases
private static boolean hasExecutionInsideSwitch(List<SwitchEntry> entries) {
    for (SwitchEntry entry : entries) {
        for (Statement stmt : entry.getStatements()) {
            String stmtStr = stmt.toString().toLowerCase();
            
            // Common execution patterns in the assignment
            if (stmtStr.contains(".execute(") || 
                stmtStr.contains(".process(") ||
                stmtStr.contains(".run(") ||
                stmtStr.contains(".calculate(") ||
                stmtStr.contains(".play(") ||
                stmtStr.contains(".showwinner(") ||
                stmtStr.contains(".aimove(") ||
                stmtStr.contains("messagecli") ||
                stmtStr.contains("print")) {
                return true;
            }
            
            // State mutations
            if (stmtStr.matches(".*\\+\\+|--.*") || 
                stmtStr.matches(".*round\\+\\+.*") ||
                stmtStr.matches(".*\\w+winrounds\\+\\+.*") ||
                stmtStr.contains("humanwinrounds++") ||
                stmtStr.contains("aiwinrounds++")) {
                return true;
            }
        }
    }
    return false;
}

private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, 
                                             ClassOrInterfaceDeclaration parent, 
                                             String studentName, 
                                             String exampleFolder,
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
                // CHECK: Is this identical override justified?
                if (!isJustifiedIdenticalOverride(childMethod, child, parent, classMap)) {
                    System.out.printf("Redundant override detected in %s.%s(): identical to parent%n",
                            child.getNameAsString(), childMethod.getSignature());

                    csvRows.add(new String[]{
                            studentName,
                            child.getNameAsString(),
                            childMethod.getNameAsString(),
                            "Redundant Override",
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
   
   // Object + framework methods always justified
String name = childMethod.getNameAsString();
if (OBJECT_METHOD_NAMES.contains(name)) return true;
if (FRAMEWORK_METHOD_NAMES.contains(name)) return true;

// Object methods always justified
if (OBJECT_METHOD_NAMES.contains(childMethod.getNameAsString())) {
    return true;
}

    String methodName = childMethod.getNameAsString();
    
    // 1. Check if parent method is abstract (immediate check)
    for (MethodDeclaration parentMethod : parentClass.getMethodsByName(methodName)) {
        if (parentMethod.isAbstract()) {
            if (parametersMatch(parentMethod, childMethod)) {
                return true;
            }
        }
    }
    
    // 2. Check if method comes from an implemented interface (directly or through inheritance)
    if (methodFromInterface(methodName, childMethod.getParameters(), parentClass, classMap)) {
        return true;
    }
    
    // 3. Check getters/setters for child fields
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
    
    // 4. Check if method uses child-specific fields
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

// Testing: Check if method originates from any interface in the hierarchy
private static boolean methodFromInterface(String methodName, 
                                          List<Parameter> parameters,
                                          ClassOrInterfaceDeclaration parentClass,
                                          Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    // Collect all interfaces in the hierarchy
    Set<String> allInterfaces = new HashSet<>();
    collectAllInterfaces(parentClass, allInterfaces, classMap);
    
    // Check each interface for the method
    for (String interfaceName : allInterfaces) {
        ClassOrInterfaceDeclaration interfaceDecl = classMap.get(interfaceName);
        if (interfaceDecl != null && interfaceDecl.isInterface()) {
            for (MethodDeclaration interfaceMethod : interfaceDecl.getMethods()) {
                if (interfaceMethod.getNameAsString().equals(methodName)) {
                    // Check if parameters match (simplified)
                    if (parametersMatch(interfaceMethod, parameters)) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

// Helper to collect all interfaces from a class (recursive)
private static void collectAllInterfaces(ClassOrInterfaceDeclaration clazz,
                                        Set<String> interfaces,
                                        Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    if (clazz == null) return;
    
    // Add directly implemented interfaces
    for (ClassOrInterfaceType ifaceType : clazz.getImplementedTypes()) {
        String ifaceName = ifaceType.getNameAsString();
        if (interfaces.add(ifaceName)) {
            // Recurse into this interface to get its parent interfaces
            ClassOrInterfaceDeclaration ifaceDecl = classMap.get(ifaceName);
            if (ifaceDecl != null) {
                collectAllInterfaces(ifaceDecl, interfaces, classMap);
            }
        }
    }
    
    // Recurse into superclass
    if (!clazz.getExtendedTypes().isEmpty()) {
        String parentName = clazz.getExtendedTypes(0).getNameAsString();
        ClassOrInterfaceDeclaration parentDecl = classMap.get(parentName);
        if (parentDecl != null) {
            collectAllInterfaces(parentDecl, interfaces, classMap);
        }
    }
}

// Testing: Check if interface method parameters match child method parameters
private static boolean parametersMatch(MethodDeclaration interfaceMethod, 
                                      List<Parameter> childParams) {
    if (interfaceMethod.getParameters().size() != childParams.size()) {
        return false;
    }
    
    for (int i = 0; i < interfaceMethod.getParameters().size(); i++) {
        String ifaceParamType = interfaceMethod.getParameter(i).getType().asString();
        String childParamType = childParams.get(i).getType().asString();
        
        // Simple type comparison - might need more sophisticated type resolution
        if (!ifaceParamType.equals(childParamType)) {
            return false;
        }
    }
    
    return true;
}

// Update the parametersMatch method for MethodDeclaration to MethodDeclaration


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

private static String removeWhitespace(String str) {
    return str.replaceAll("\\s+", "");
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

private static MethodDeclaration findMatchingParentMethod(MethodDeclaration childMethod, 
                                                          ClassOrInterfaceDeclaration parent) {
    for (MethodDeclaration parentMethod : parent.getMethods()) {
        if (!parentMethod.getBody().isPresent()) continue;
        
        // Check names match
        if (!childMethod.getNameAsString().equals(parentMethod.getNameAsString())) {
            continue;
        }
        
        // Check parameter counts match
        if (childMethod.getParameters().size() != parentMethod.getParameters().size()) {
            continue;
        }
        
        // Check parameter types (simplified)
        boolean paramsMatch = true;
        for (int i = 0; i < childMethod.getParameters().size(); i++) {
            String childType = childMethod.getParameter(i).getType().asString();
            String parentType = parentMethod.getParameter(i).getType().asString();
            
            // Simple type comparison
            if (!childType.equals(parentType)) {
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

private static String extractMethodBody(MethodDeclaration method) {
    BlockStmt body = method.getBody().get();
    
    // Clone and remove comments
    BlockStmt clone = body.clone();
    clone.getAllContainedComments().forEach(Comment::remove);
    
    // Normalize
    return clone.toString()
               .replaceAll("\\s+", " ")
               .replaceAll("\\s*;\\s*", ";")
               .trim();
}

private static boolean isIdenticalOverrideJustified(MethodDeclaration method, 
                                                    Set<String> childFields) {
    String methodName = method.getNameAsString();
    
    // Getter method (getXxx) - check if child has field 'xxx'
    if (methodName.startsWith("get") && methodName.length() > 3) {
        String fieldName = Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
        return childFields.contains(fieldName);
    }
    
    // Setter method (setXxx) - check if child has field 'xxx'
    if (methodName.startsWith("set") && methodName.length() > 3) {
        String fieldName = Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
        return childFields.contains(fieldName);
    }
    
    // Boolean getter (isXxx)
    if (methodName.startsWith("is") && methodName.length() > 2) {
        String fieldName = Character.toLowerCase(methodName.charAt(2)) + methodName.substring(3);
        return childFields.contains(fieldName);
    }
    
    // Method might access multiple fields - check body
    if (method.getBody().isPresent()) {
        String body = method.getBody().get().toString();
        for (String field : childFields) {
            if (body.contains(field) || body.contains("this." + field)) {
                return true;
            }
        }
    }
    
    return false;
}

private static String extractPureCode(BlockStmt body) {
    // Clone to avoid modifying original
    BlockStmt clone = body.clone();
    
    // Remove ALL comments
    clone.getAllContainedComments().forEach(Comment::remove);
    
    // Get string and strip EVERYTHING non-essential
    String code = clone.toString();
    
    // Remove: comments, whitespace, braces, semicolons, parentheses
    code = code.replaceAll("//.*|/\\*(.|\\R)*?\\*/", "")  // Comments
               .replaceAll("[\\s{}\\(\\);]", "")         // All whitespace and punctuation
               .trim();
    
    return code;
}

private static boolean methodsMatch(MethodDeclaration m1, MethodDeclaration m2) {
    if (!m1.getNameAsString().equals(m2.getNameAsString())) return false;
    if (m1.getParameters().size() != m2.getParameters().size()) return false;
    
    for (int i = 0; i < m1.getParameters().size(); i++) {
        String t1 = m1.getParameter(i).getType().asString();
        String t2 = m2.getParameter(i).getType().asString();
        if (!t1.equals(t2)) return false;
    }
    
    return true;
}

private static String normalizeCode(String code) {
    // Simple normalization: remove comments and extra whitespace
    code = code.replaceAll("//.*|/\\*(.|\\R)*?\\*/", "") // Remove comments
               .replaceAll("\\s+", " ")                   // Collapse whitespace
               .trim();
    return code;
}

// Helper to identify trivial getters/setters
private static boolean isTrivialGetterSetter(String body) {
    return body.matches("return\\s+\\w+;") || 
           body.matches("this\\.\\w+\\s*=\\s*\\w+;");
}

// Testing: Skip comparison for certain method patterns
private static boolean shouldSkipOverrideCheck(MethodDeclaration parentMethod,
                                               MethodDeclaration childMethod) {
    String parentName = ((ClassOrInterfaceDeclaration) parentMethod.getParentNode().get()).getNameAsString();
    String childName = ((ClassOrInterfaceDeclaration) childMethod.getParentNode().get()).getNameAsString();
    
    // Skip common inheritance patterns
    if (parentName.equals("Policy") && 
        (childName.equals("Car") || childName.equals("Home") || childName.equals("Life"))) {
        return true;
    }
    
    // Skip if parent is abstract
    if (parentMethod.isAbstract()) {
        return true;
    }
    
    return false;
}

private static boolean methodDeclaredInSuperclass(
        String methodName,
        Set<String> classNames,
        Map<String, ClassOrInterfaceDeclaration> classMap) {

    for (String className : classNames) {
        ClassOrInterfaceDeclaration clazz = classMap.get(className);
        while (clazz != null) {
            if (!clazz.getExtendedTypes().isEmpty()) {
                String parentName = clazz.getExtendedTypes(0).getNameAsString();
                ClassOrInterfaceDeclaration parent = classMap.get(parentName);
                if (parent != null) {
                    for (MethodDeclaration m : parent.getMethodsByName(methodName)) {
                        return true;
                    }
                }
                clazz = parent;
            } else {
                break;
            }
        }
    }
    return false;
}



private static boolean methodDeclaredInCommonSuperclass(
        String methodName,
        Set<String> classNames,
        Map<String, ClassOrInterfaceDeclaration> classMap) {

    for (String className : classNames) {
        ClassOrInterfaceDeclaration clazz = classMap.get(className);

        while (clazz != null) {
            if (!clazz.getExtendedTypes().isEmpty()) {
                String parentName = clazz.getExtendedTypes(0).getNameAsString();
                ClassOrInterfaceDeclaration parent = classMap.get(parentName);
                if (parent == null) break;

                for (MethodDeclaration m : parent.getMethodsByName(methodName)) {
                    if (m.isAbstract()) {
                        return true;
                    }
                }
                clazz = parent;
            } else {
                break;
            }
        }
    }
    return false;
}


// Check if classes share any common ancestor (superclass or interface)
private static boolean haveCommonAncestor(Set<String> classNames, Map<String, ClassOrInterfaceDeclaration> classMap) {
    if (oneIsAncestorOfAnother(classNames, classMap)) return true;
    if (shareCommonAncestor(classNames, classMap)) return true;
    return false;
}

private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap,
                                             String studentName,
                                             String exampleFolder) {

    Map<String, Set<String>> methodToClasses = new HashMap<>();

    // Collect all non-static, non-main methods by full signature
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            // Skip test classes
    if (isTestClass(clazz)) continue;

    // Skip internal data structures
    if (looksLikeInternalNode(clazz)) continue;
        for (MethodDeclaration method : clazz.getMethods()) {

    if (isMainMethod(method) || method.isStatic()) continue;

    // Only public API matters
    if (!method.isPublic()) continue;

    // Object + framework methods
    String name = method.getNameAsString();
    if (OBJECT_METHOD_NAMES.contains(name)) continue;
    if (FRAMEWORK_METHOD_NAMES.contains(name)) continue;

    // Allow small but non-trivial methods
if (method.getBody().isEmpty()) continue;

int stmtCount = method.getBody().get().getStatements().size();

// Skip only trivial one-liners that are pure forwarding
if (stmtCount == 1 &&
    method.getBody().get().getStatement(0).isReturnStmt()) {
    continue;
}


    // Skip Object overrides
    if (OBJECT_METHOD_NAMES.contains(method.getNameAsString())) continue;

    String sig = methodSignatureWithoutVisibility(method);
    methodToClasses
        .computeIfAbsent(sig, k -> new HashSet<>())
        .add(clazz.getNameAsString());
}

    }

    // For each method appearing in multiple classes, check ancestry
    for (Map.Entry<String, Set<String>> entry : methodToClasses.entrySet()) {
        Set<String> classes = entry.getValue();
if (classes.size() < 2) continue;

// Require >= 2 shared methods between same classes
long sharedCount =
    methodToClasses.entrySet().stream()
        .filter(e -> e.getValue().equals(classes))
        .count();

if (sharedCount < 2) continue;


        if (haveCommonAncestor(classes, classMap)) continue;
        
        // Check if this is a delegation pattern before flagging
        if (isDelegationPattern(entry.getKey(), classes, classMap)) continue;

        // Check if this is an internal node
        if (classes.stream().anyMatch(c -> looksLikeInternalNode(classMap.get(c)))) continue;

        // Skip internal node / data-holder classes
boolean anyInternal =
    classes.stream()
        .map(classMap::get)
        .anyMatch(c -> c != null && looksLikeInternalNode(c));

if (anyInternal) continue;

Set<ClassOrInterfaceDeclaration> classDecls =
    classes.stream()
        .map(classMap::get)
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());

if (sharedCount < 2) continue;

// Require weak relationship
if (!weaklyRelated(classDecls)) continue;

        // True missing inheritance
        csvRows.add(new String[]{
                studentName,
                String.join(";", classes),
                entry.getKey(),
                "Missing Inheritance",
                "Classes define same method (including return type and visibility) but do not share superclass or interface"
        });

        System.out.printf("Missing inheritance: %s | %s -> %s%n",
                studentName, classes, entry.getKey());
    }
}

private static boolean weaklyRelated(Set<ClassOrInterfaceDeclaration> classes) {
    List<ClassOrInterfaceDeclaration> list = new ArrayList<>(classes);

    for (int i = 0; i < list.size(); i++) {
        for (int j = i + 1; j < list.size(); j++) {

            // Name similarity
            String a = list.get(i).getNameAsString().toLowerCase();
            String b = list.get(j).getNameAsString().toLowerCase();
            if (a.contains(b) || b.contains(a)) return true;

            // Shared field or parameter types
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
    // Name-based
    if (clazz.getNameAsString().endsWith("Test")) return true;

    // JUnit annotations
    if (!clazz.findAll(MarkerAnnotationExpr.class).isEmpty()) return true;

    // Imports org.junit.*
    return clazz.findCompilationUnit()
        .flatMap(cu -> cu.getImports().stream()
            .map(i -> i.getNameAsString())
            .filter(n -> n.startsWith("org.junit"))
            .findAny())
        .isPresent();
}


private static boolean looksLikeInternalNode(ClassOrInterfaceDeclaration clazz) {
    boolean isGeneric = !clazz.getTypeParameters().isEmpty();

    boolean hasNextField =
        clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .anyMatch(v -> v.getNameAsString().equalsIgnoreCase("next"));

    boolean hasValueField =
        clazz.getFields().stream()
            .flatMap(f -> f.getVariables().stream())
            .anyMatch(v -> v.getNameAsString().equalsIgnoreCase("value"));

    return isGeneric && (hasNextField || hasValueField);
}



// Testing: Check if the method implementation shows delegation
private static boolean isDelegationPattern(String methodSignature, 
                                           Set<String> classNames, 
                                           Map<String, ClassOrInterfaceDeclaration> classMap) {
    
    // Only check pairs of classes (common delegation pattern)
    if (classNames.size() != 2) return false;
    
    List<String> classesList = new ArrayList<>(classNames);
    String classA = classesList.get(0);
    String classB = classesList.get(1);
    
    // Get the method bodies
    MethodDeclaration methodA = findMethod(classA, methodSignature, classMap);
    MethodDeclaration methodB = findMethod(classB, methodSignature, classMap);
    
    if (methodA == null || methodB == null) return false;
    
    // Check if one method body just calls the other (delegation)
    return isSimpleDelegate(methodA, classB, classMap) || 
           isSimpleDelegate(methodB, classA, classMap);
}

// Testing: Find a method by signature in a class
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

// Testing: Check if a method is a simple delegation to another class
private static boolean isSimpleDelegate(MethodDeclaration method, 
                                        String delegateClassName,
                                        Map<String, ClassOrInterfaceDeclaration> classMap) {
    if (!method.getBody().isPresent()) return false;
    
    BlockStmt body = method.getBody().get();
    
    // A simple delegation typically has:
    // 1. A field of the delegate type
    // 2. A single method call to that field
    
    // Check for field of delegate type in the class
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
    
    // Count statements in the method
    List<Statement> statements = body.getStatements();
    if (statements.size() != 1) return false;
    
    Statement stmt = statements.get(0);
    
    // Check if it's an expression statement (method call)
    if (stmt.isExpressionStmt()) {
        ExpressionStmt exprStmt = stmt.asExpressionStmt();
        Expression expr = exprStmt.getExpression();
        
        // Check if it's a method call
        if (expr.isMethodCallExpr()) {
            MethodCallExpr call = expr.asMethodCallExpr();
            
            // Check if the scope is a name (field name)
            if (call.getScope().isPresent()) {
                Expression scope = call.getScope().get();
                
                // Could be a field access like "database.method()" or just "method()"
                // maybe be more lenient here
                return true;
            }
        }
    }
    
    return false;
}

// Return true if any class is an ancestor of another
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

// Return true if classes share a common ancestor
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

    // Recursively add superclass
    if (!clazz.getExtendedTypes().isEmpty()) {
        String parent = clazz.getExtendedTypes(0).getNameAsString();
        if (!parent.equals("Object") && classMap.containsKey(parent)) {
            ancestors.add(parent);
            ancestors.addAll(getAllAncestors(parent, classMap));
        }
    }

    // Recursively add implemented interfaces
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

// Check if method is main
private static boolean isMainMethod(MethodDeclaration m) {
    return m.getNameAsString().equals("main")
            && m.getParameters().size() == 1
            && m.getParameter(0).getType().asString().equals("String[]");
}


private static void detectRedundantSuperclass(Map<String, ClassOrInterfaceDeclaration> classMap, 
                                              String studentName, 
                                              String exampleFolder) {
    
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (clazz.getExtendedTypes().isEmpty()) continue;

        String parentName = clazz.getExtendedTypes().get(0).getNameAsString();
        
        // Skip common cases that aren't actually redundant
        if (shouldSkipInheritanceCheck(clazz.getNameAsString(), parentName)) {
            continue;
        }

        ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
        if (parentClass == null) continue;

        // Get all methods that child could potentially override
        Set<String> overridableMethods = new HashSet<>();
        for (MethodDeclaration pm : parentClass.getMethods()) {
            // Only non-private, non-final methods can be overridden
            if (!pm.isPrivate() && !pm.isFinal()) {
                overridableMethods.add(getMethodSignature(pm));
            }
        }
        
        if (overridableMethods.isEmpty()) {
            // Parent has no overridable methods - check if child has ANY reason to extend
            if (!hasValidExtensionReason(clazz, parentClass)) {
                flagRedundantInheritance(studentName, exampleFolder, clazz.getNameAsString(), parentName);
            }
            continue;
        }
        
        // Check if child overrides ANY overridable method
        boolean overridesAny = false;
        for (MethodDeclaration cm : clazz.getMethods()) {
            if (overridableMethods.contains(getMethodSignature(cm))) {
                overridesAny = true;
                break;
            }
        }
        
        if (!overridesAny && !hasValidExtensionReason(clazz, parentClass)) {
            flagRedundantInheritance(studentName, exampleFolder, clazz.getNameAsString(), parentName);
        }
    }
}

private static boolean hasValidExtensionReason(ClassOrInterfaceDeclaration child, 
                                               ClassOrInterfaceDeclaration parent) {
    
    // 1: Child adds its own fields (specialization)
    if (!child.getFields().isEmpty()) {
        return true;
    }
    
    // 2: Child uses super() in constructors
    for (ConstructorDeclaration constructor : child.getConstructors()) {
        BlockStmt body = constructor.getBody();  // Direct access, not Optional
        for (Statement stmt : body.getStatements()) {
            if (stmt.isExplicitConstructorInvocationStmt()) {
                return true;
            }
        }
    }
    
    // 3: Child accesses inherited protected/public fields
    Set<String> parentNonPrivateFields = new HashSet<>();
    for (FieldDeclaration field : parent.getFields()) {
        if (!field.isPrivate()) {
            for (VariableDeclarator var : field.getVariables()) {
                parentNonPrivateFields.add(var.getNameAsString());
            }
        }
    }
    
    // Check all child methods for use of non-private parent fields
    for (MethodDeclaration method : child.getMethods()) {
        Optional<BlockStmt> bodyOpt = method.getBody();  // Method returns Optional
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
    
    // 4: Parent is abstract or interface
    if (parent.isAbstract() || parent.isInterface()) {
        return true;
    }
    
    // OO5: Child has non-private access to parent fields
    // (Checking for field declarations that might use parent fields)
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

private static boolean shouldSkipInheritanceCheck(String childName, String parentName) {
    // Skip Object (every class implicitly extends Object)
    if (parentName.equals("Object")) return true;
    
    // Skip test classes
    if (childName.matches(".*[Tt]est.*") || 
        childName.matches("Task\\d+") ||
        childName.equals("YourTests")) {
        return true;
    }
    
    // Skip known valid inheritance patterns for this assignment
    if (parentName.equals("Policy") && 
        (childName.equals("Car") || childName.equals("Home") || childName.equals("Life"))) {
        return true;
    }
    
    return false;
}



private static void flagRedundantInheritance(String studentName, String exampleFolder, 
                                             String childName, String parentName) {
    System.out.printf("Redundant inheritance detected in %s|%s: Class %s inherits from %s but does not override or reuse any superclass method.%n",
            studentName, exampleFolder, childName, parentName);

    csvRows.add(new String[]{
            studentName,
            childName,
            "",
            "Redundant Inheritance",
            "Class inherits but does not override/reuse superclass methods"
    });
}}