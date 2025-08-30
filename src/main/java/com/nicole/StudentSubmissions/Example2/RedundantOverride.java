package com.nicole.StudentSubmissions.Example2;

public class RedundantOverride {
    void speak() {
        System.out.println("Animal speaks");
        
    }

    void hello(String s, int i) {
    }


    public static void main(String[] args) {
        RedundantOverride animal = new RedundantOverride();
        animal.speak();

        Cat cat = new Cat();
        cat.speak();
    }
}

class Cat extends RedundantOverride {
    
    void speak() {
        System.out.println("Animal speaks"); // Redundant override - same as parent
    }

    
    void hello(String s, int i) {   
        
    }
}