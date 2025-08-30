package com.nicole;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

public class LspAst {

    public static void main(String[] args) throws Exception {
        File submissionsDir = new File("src/main/java/com/nicole/StudentSubmissions");
        if (!submissionsDir.exists()) {
            System.err.println("Submissions folder not found: " + submissionsDir.getAbsolutePath());
            return;
        }

        List<StudentClasses> allStudents = new ArrayList<>();

        File[] studentDirs = submissionsDir.listFiles();
        if (studentDirs != null) {
            for (File studentDir : studentDirs) {
                if (!studentDir.isDirectory()) continue;
                String studentName = studentDir.getName();
                Path studentPath = studentDir.toPath().toRealPath();

                List<CompilationUnit> units = new ArrayList<>();
                JavaParser parser = new JavaParser();

                // Walk all Example* folders
                try (Stream<Path> walk = Files.walk(studentPath)) {
                    walk.filter(Files::isRegularFile)
                        .filter(p -> p.getFileName().toString().endsWith(".java"))
                        .filter(p -> pathHasExampleDir(p, studentPath))
                        .forEach(p -> {
                            try {
                                ParseResult<CompilationUnit> result = parser.parse(p);
                                if (result.isSuccessful() && result.getResult().isPresent()) {
                                    CompilationUnit cu = result.getResult().get();
                                    cu.setStorage(p);
                                    units.add(cu);
                                } else {
                                    System.err.println("Could not parse: " + p);
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        });
                }

                List<ClassInfo> classList = new ArrayList<>();
                for (CompilationUnit cu : units) {
                    for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                        String className = clazz.getNameAsString();
                        String superclass = clazz.getExtendedTypes().isEmpty() ? null :
                                clazz.getExtendedTypes(0).getNameAsString();

                        List<String> methods = new ArrayList<>();
                        for (MethodDeclaration method : clazz.getMethods()) {
                            methods.add(method.getNameAsString());
                        }

                        classList.add(new ClassInfo(className, superclass, methods));
                    }
                }

                allStudents.add(new StudentClasses(studentName, classList));
            }
        }

        // Write JSON
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter("lsp_ast.json")) {
            gson.toJson(allStudents, writer);
        }

        System.out.println("Export complete: lsp_ast.json");
    }

    private static boolean pathHasExampleDir(Path filePath, Path studentDirPath) {
        try {
            Path current = filePath.getParent().toRealPath();
            Path studentBase = studentDirPath.toRealPath();
            while (current != null && current.startsWith(studentBase)) {
                String name = current.getFileName().toString().toLowerCase();
                if (name.startsWith("example")) return true;
                current = current.getParent();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // ------------------------
    // Helper classes for JSON
    // ------------------------
    static class StudentClasses {
        String student;
        List<ClassInfo> classes;

        StudentClasses(String student, List<ClassInfo> classes) {
            this.student = student;
            this.classes = classes;
        }
    }

    static class ClassInfo {
        String name;
        String superclass; // null if no superclass
        List<String> methods;

        ClassInfo(String name, String superclass, List<String> methods) {
            this.name = name;
            this.superclass = superclass;
            this.methods = methods;
        }
    }
}
