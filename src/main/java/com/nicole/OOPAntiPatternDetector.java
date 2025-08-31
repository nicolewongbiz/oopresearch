package com.nicole;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.comments.Comment;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.utils.SourceRoot;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;



public class OOPAntiPatternDetector {

    private static List<String[]> csvRows = new ArrayList<>();

public static void main(String[] args) throws Exception {
    File submissionsDir = new File("../assignment-1/assignment-1-repos");
    if (!submissionsDir.exists()) {
        System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
        return;
    }

    // CSV header
    csvRows.add(new String[]{"Student", "Class", "Method", "IssueType", "Details"});

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
                    detectRedundantOverrides(clazz, parentClass, studentName, "N/A");
                }
            }
        }

        detectMissingInheritance(classMap, studentName, "N/A");
        detectRedundantSuperclass(classMap, studentName, "N/A");
    }

    writeCsv("oop_antipattern_results.csv");
}


private static void writeCsv(String fileName) {
    try (PrintWriter pw = new PrintWriter(new File(fileName))) {
        for (String[] row : csvRows) {
            // naive CSV escaping: wrap fields with double quotes and escape inner quotes
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
        Path current = filePath.getParent().toRealPath(); // canonical form
        Path studentBase = studentDirPath.toRealPath();   // canonical form

        while (current != null && current.startsWith(studentBase)) {
            Path name = current.getFileName();
            if (name != null) {
                String s = name.toString().toLowerCase();
                if (s.startsWith("assignment-1")) return true; // case-insensitive
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

private static void removeAllComments(Node node) {
    node.getAllContainedComments().forEach(Comment::remove);
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
                    System.out.printf("Enum misuse detected in %s.%s(): switch on enum%n",
                            clazz.getNameAsString(),
                            method.getNameAsString());

                    csvRows.add(new String[]{
                            studentName,
                            clazz.getNameAsString(),
                            method.getNameAsString(),
                            "Enum Misuse",
                            "Switch on enum"
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

private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, ClassOrInterfaceDeclaration parent, String studentName, String exampleFolder) {
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

private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap, String studentName, String exampleFolder) {
    Map<String, Set<String>> methodToClasses = new HashMap<>();

    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        for (MethodDeclaration method : clazz.getMethods()) {
            String name = method.getNameAsString();
            if (name.equals("main") &&
                method.getParameters().size() == 1 &&
                method.getParameter(0).getType().asString().equals("String[]")) {
                continue;
            }

            String signature = name + "/" + method.getParameters().size();
            methodToClasses.computeIfAbsent(signature, k -> new HashSet<>())
                           .add(clazz.getNameAsString());
        }
    }

    for (Map.Entry<String, Set<String>> entry : methodToClasses.entrySet()) {
        Set<String> classNames = entry.getValue();
        if (classNames.size() < 2) continue;

        if (!shareCommonAncestor(classNames, classMap)) {
            System.out.printf("Missing inheritance in %s|%s: Classes %s all define method %s but do not share a superclass%n",
                    studentName, exampleFolder, classNames, entry.getKey());

            // write to CSV (one row per group-method)
            csvRows.add(new String[]{
                    studentName,
                    String.join(";", classNames),
                    entry.getKey(),
                    "Missing Inheritance",
                    "Classes define same method but do not share superclass"
            });
        }
    }
}

private static boolean shareCommonAncestor(Set<String> classes, Map<String, ClassOrInterfaceDeclaration> classMap) {
    List<Set<String>> ancestorSets = new ArrayList<>();

    for (String className : classes) {
        Set<String> ancestors = new HashSet<>();
        String current = className;

        while (true) {
            ClassOrInterfaceDeclaration clazz = classMap.get(current);
            if (clazz == null || clazz.getExtendedTypes().isEmpty()) break;
            String parent = clazz.getExtendedTypes(0).getNameAsString();
            if (parent.equals("Object")) break;
            ancestors.add(parent);
            current = parent;
        }

        ancestorSets.add(ancestors);
    }

    if (ancestorSets.isEmpty()) return false;

    Set<String> intersection = new HashSet<>(ancestorSets.get(0));
    for (Set<String> s : ancestorSets) {
        intersection.retainAll(s);
    }

    return !intersection.isEmpty();
}

private static void detectRedundantSuperclass(Map<String, ClassOrInterfaceDeclaration> classMap, String studentName, String exampleFolder) {
    for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
        if (clazz.getExtendedTypes().isEmpty()) continue;

        String parentName = clazz.getExtendedTypes(0).getNameAsString();
        ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
        if (parentClass == null) continue;

        List<MethodDeclaration> parentMethods = parentClass.getMethods();
        List<MethodDeclaration> childMethods = clazz.getMethods();

        if (parentMethods.isEmpty()) continue;

        boolean overrides = false;
        Set<String> parentSignatures = new HashSet<>();
        for (MethodDeclaration pm : parentMethods) {
            parentSignatures.add(pm.getSignature().asString());
        }

        for (MethodDeclaration cm : childMethods) {
            if (parentSignatures.contains(cm.getSignature().asString())) {
                overrides = true;
                break;
            }
        }

        if (!overrides) {
            System.out.printf("Redundant inheritance detected in %s|%s: Class %s inherits from %s but does not override or reuse any superclass method.%n",
                    studentName, exampleFolder, clazz.getNameAsString(), parentName);

            csvRows.add(new String[]{
                    studentName,
                    clazz.getNameAsString(),
                    "",
                    "Redundant Inheritance",
                    "Class inherits but does not override/reuse superclass methods"
            });
        }
    }
}}