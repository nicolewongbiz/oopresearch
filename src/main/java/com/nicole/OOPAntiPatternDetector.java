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
import java.nio.file.Paths;
import java.util.*;
import java.io.PrintWriter;

public class OOPAntiPatternDetector {

    private static List<String[]> csvRows = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        File submissionsDir = new File("src/main/java/com/nicole/StudentSubmissions");
        if (!submissionsDir.exists()) {
            System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
            return;
        }

        csvRows.add(new String[]{"Student", "Class", "Method", "IssueType", "Details"});

        // Iterate all .java files in student subfolders
        List<File> javaFiles = new ArrayList<>();
        Map<String, String> fileToStudent = new HashMap<>();
        for (File studentDir : submissionsDir.listFiles()) {
            if (!studentDir.isDirectory()) continue;
            String studentName = studentDir.getName();
            for (File javaFile : studentDir.listFiles()) {
                if (javaFile.getName().endsWith(".java")) {
                    javaFiles.add(javaFile);
                    fileToStudent.put(javaFile.getAbsolutePath(), studentName);
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
                cu.setStorage(f.toPath());  // remember the file path
                units.add(cu);
            } else {
                System.err.println("Could not parse: " + f.getAbsolutePath());
                result.getProblems().forEach(System.err::println);
            }
        }

        Map<String, ClassOrInterfaceDeclaration> classMap = new HashMap<>();
        for (CompilationUnit cu : units) {
            cu.findAll(ClassOrInterfaceDeclaration.class)
              .forEach(clazz -> classMap.put(clazz.getNameAsString(), clazz));
        }

        // declare all enums
        Set<String> allEnumNames = collectAllEnumNames(units);

        System.out.println("Parsed classes:");
        for (String className : classMap.keySet()) {
             System.out.println(" - " + className);
        }

        System.out.println("=== Enum misuse detection ===");
        for (CompilationUnit cu : units) {
            for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                String studentName = fileToStudent.get(cu.getStorage().get().getPath().toAbsolutePath().toString());
                detectEnumTypeChecks(clazz, allEnumNames, studentName);
            }
        }

        System.out.println("=== Type checking ===");
        for (CompilationUnit cu : units) {
            for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                String studentName = fileToStudent.get(cu.getStorage().get().getPath().toAbsolutePath().toString());
                if (hasTypeField(clazz)) {
                    detectTypeCheckingInMethods(clazz, studentName);
                }
            }
        }

        System.out.println("\n=== Redundant overrides ===");
        for (CompilationUnit cu : units) {
            for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                String studentName = fileToStudent.get(cu.getStorage().get().getPath().toAbsolutePath().toString());
                if (!clazz.getExtendedTypes().isEmpty()) {
                    String parentName = clazz.getExtendedTypes(0).getNameAsString();
                    ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
                    if (parentClass != null) {
                        detectRedundantOverrides(clazz, parentClass, studentName);
                    }
                }
            }
        }

        System.out.println("\n=== Missing inheritance detection ===");
        detectMissingInheritance(classMap);

        System.out.println("\n=== Redundant superclass detection ===");
        detectRedundantSuperclass(classMap);

        // write CSV
        writeCsv("oop_antipattern_results.csv");
    }

    private static void writeCsv(String fileName) {
        try (PrintWriter pw = new PrintWriter(new File(fileName))) {
            for (String[] row : csvRows) {
                pw.println(String.join(",", row));
            }
            System.out.println("CSV results written to " + fileName);
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

    private static void detectTypeCheckingInMethods(ClassOrInterfaceDeclaration clazz, String studentName) {
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

    private static void detectEnumTypeChecks(ClassOrInterfaceDeclaration clazz, Set<String> allEnumNames, String studentName) {
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

    private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, ClassOrInterfaceDeclaration parent, String studentName) {
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

    private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap) {
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
                System.out.printf("Missing inheritance: Classes %s all define method %s but do not share a superclass%n",
                        classNames, entry.getKey());
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

    private static void detectRedundantSuperclass(Map<String, ClassOrInterfaceDeclaration> classMap) {
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
                System.out.printf("Redundant inheritance detected: Class %s inherits from %s but does not override or reuse any superclass method.%n",
                        clazz.getNameAsString(), parentName);
            }
        }
    }
}
