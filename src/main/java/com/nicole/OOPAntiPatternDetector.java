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

public class OOPAntiPatternDetector {

    public static void main(String[] args) throws Exception {
        File projectDir = new File("src/main/java");
        SourceRoot sourceRoot = new SourceRoot(Paths.get(projectDir.toURI()));
        List<ParseResult<CompilationUnit>> parseResults = sourceRoot.tryToParse();

        List<CompilationUnit> units = new ArrayList<>();
        for (ParseResult<CompilationUnit> result : parseResults) {
            if (result.isSuccessful() && result.getResult().isPresent()) {
                units.add(result.getResult().get());
            } else {
                System.err.println("Warning: Could not parse file:");
                result.getProblems().forEach(problem -> System.err.println("  " + problem));
            }
        }

        Map<String, ClassOrInterfaceDeclaration> classMap = new HashMap<>();
        for (CompilationUnit cu : units) {
            cu.findAll(ClassOrInterfaceDeclaration.class)
              .forEach(clazz -> classMap.put(clazz.getNameAsString(), clazz));
        }

        // <-- allEnumNames declared here
        Set<String> allEnumNames = collectAllEnumNames(units);

        System.out.println("Parsed classes:");
        for (String className : classMap.keySet()) {
             System.out.println(" - " + className);
        }

        System.out.println("=== Enum misuse detection ===");
        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            detectEnumTypeChecks(clazz, allEnumNames);
        }

        System.out.println("=== Type checking ===");
        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            if (hasTypeField(clazz)) {
                detectTypeCheckingInMethods(clazz);
            }
        }

        System.out.println("\n=== Redundant overrides ===");
        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
            if (!clazz.getExtendedTypes().isEmpty()) {
                String parentName = clazz.getExtendedTypes(0).getNameAsString();
                ClassOrInterfaceDeclaration parentClass = classMap.get(parentName);
                if (parentClass != null) {
                    detectRedundantOverrides(clazz, parentClass);
                }
            }
        }

        System.out.println("\n=== Missing inheritance detection ===");
        detectMissingInheritance(classMap);

        System.out.println("\n=== Redundant superclass detection ===");
        detectRedundantSuperclass(classMap);
    }

    // private static void collectClassesRecursively(TypeDeclaration<?> type, Map<String, ClassOrInterfaceDeclaration> classMap) {
    //     if (type.isClassOrInterfaceDeclaration()) {
    //         ClassOrInterfaceDeclaration clazz = (ClassOrInterfaceDeclaration) type;
    //         classMap.put(clazz.getNameAsString(), clazz);

    //         // Recursively collect inner classes
    //         for (BodyDeclaration<?> member : clazz.getMembers()) {
    //             if (member instanceof TypeDeclaration<?>) {
    //                 collectClassesRecursively((TypeDeclaration<?>) member, classMap);
    //             }
    //         }
    //     }
    // }

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

    private static void detectTypeCheckingInMethods(ClassOrInterfaceDeclaration clazz) {
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

    private static void detectEnumTypeChecks(ClassOrInterfaceDeclaration clazz, Set<String> allEnumNames) {
    for (FieldDeclaration field : clazz.getFields()) {
        String fieldName = field.getVariables().get(0).getNameAsString();
        String fieldType = field.getElementType().asString();

        // Skip non-enum fields
        if (!allEnumNames.contains(fieldType)) continue;

        for (MethodDeclaration method : clazz.getMethods()) {
            Optional<BlockStmt> body = method.getBody();
            if (!body.isPresent()) continue;

            // Case 1: if (enumField == ENUM_VALUE) or !=
            body.get().findAll(IfStmt.class).forEach(ifStmt -> {
                Expression cond = ifStmt.getCondition();
                if (isEnumComparison(cond, fieldName)) {
                    System.out.printf(
                        "Enum misuse detected in %s.%s(): enum comparison%n",
                        clazz.getNameAsString(),
                        method.getNameAsString()
                    );
                }
            });

            // Case 2: switch(enumField) { ... }
            body.get().findAll(SwitchStmt.class).forEach(switchStmt -> {
                Expression selector = switchStmt.getSelector();
                if (selector.isNameExpr() && selector.asNameExpr().getNameAsString().equals(fieldName)) {
                    System.out.printf(
                        "Enum misuse detected in %s.%s(): switch on enum%n",
                        clazz.getNameAsString(),
                        method.getNameAsString()
                    );
                }
            });
        }
    }
}

// Checks if the expression is comparing the enum field using == or !=
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

// Checks if an expression is the given field
private static boolean isFieldName(Expression expr, String name) {
    return expr.isNameExpr() && expr.asNameExpr().getNameAsString().equals(name);
}

// Checks if the given type is an enum in the same compilation unit
private static boolean isEnumType(ClassOrInterfaceDeclaration clazz, String typeName) {
    List<EnumDeclaration> enums = clazz.findCompilationUnit()
                                      .map(cu -> cu.findAll(EnumDeclaration.class))
                                      .orElse(Collections.emptyList());
    for (EnumDeclaration e : enums) {
        if (e.getNameAsString().equals(typeName)) return true;
    }
    return false;
}



    private static void detectRedundantOverrides(ClassOrInterfaceDeclaration child, ClassOrInterfaceDeclaration parent) {
        Map<String, MethodDeclaration> parentMethods = new HashMap<>();
        for (MethodDeclaration pm : parent.getMethods()) {
            parentMethods.put(pm.getSignature().asString(), pm);
        }

        for (MethodDeclaration childMethod : child.getMethods()) {
            String sig = childMethod.getSignature().asString();
            // System.out.println(sig);
        

            if (!parentMethods.containsKey(sig)) continue;

            // boolean hasOverrideAnnotation = childMethod.getAnnotations().stream()
            //         .anyMatch(a -> a.getNameAsString().equals("Override"));
            // if (!hasOverrideAnnotation) continue;

            MethodDeclaration parentMethod = parentMethods.get(sig);

            if (parentMethod.getBody().isPresent() && childMethod.getBody().isPresent()) {
                BlockStmt parentBody = parentMethod.getBody().get();
                BlockStmt childBody = childMethod.getBody().get();

                // Remove all comments from both bodies
                removeAllComments(parentBody);
                removeAllComments(childBody);

                // Normalize whitespace and compare
                String parentBodyStr = parentBody.toString().trim().replaceAll("\\s+", " ");
                String childBodyStr = childBody.toString().trim().replaceAll("\\s+", " ");

                // System.out.println("Parent method body: " + parentBodyStr);
                // System.out.println("Child method body:  " + childBodyStr);

                if (parentBodyStr.equals(childBodyStr)) {
                    System.out.printf("Redundant override detected in %s.%s(): identical to parent%n",
                            child.getNameAsString(), childMethod.getSignature());
                            
                }
            }
        }
    }

    private static void detectMissingInheritance(Map<String, ClassOrInterfaceDeclaration> classMap) {
        Map<String, Set<String>> methodToClasses = new HashMap<>();

        for (ClassOrInterfaceDeclaration clazz : classMap.values()) {
    for (MethodDeclaration method : clazz.getMethods()) {
        // Get method name
        String name = method.getNameAsString();

        // Skip main(String[] args)
        if (name.equals("main") &&
            method.getParameters().size() == 1 &&
            method.getParameter(0).getType().asString().equals("String[]")) {
            continue;
        }

        // Use name + parameter count as signature
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

        // If parent has no methods, skips (for now? not too sure)
        if (parentMethods.isEmpty()) continue;

        // Check if child overrides any parent method
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

        // If no overrides, flag as redundant superclass
        if (!overrides) {
            System.out.printf("Redundant inheritance detected: Class %s inherits from %s but does not override or reuse any superclass method.%n",
                    clazz.getNameAsString(), parentName);
        }
    }
}

}
