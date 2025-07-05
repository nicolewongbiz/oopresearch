package com.nicole;

public class Animal {

    // instance variable
    String type;

    // constructor
    public Animal(String type) {
        this.type = type;
    }

    // method
    void speak() {
        if (type.equals("dog")) {
            System.out.println("Woof");
        } else if (type.equals("cat")) {
            System.out.println("Meow");
        }
    }

    // main method to run the code
    public static void main(String[] args) {
        Animal a = new Animal("dog");
        a.speak();  // prints Woof
    }
}
