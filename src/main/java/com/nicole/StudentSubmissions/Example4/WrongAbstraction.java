package com.nicole.StudentSubmissions.Example4;

public class WrongAbstraction {

    class Animal {
    void bark() {
        System.out.println("Is barking");
    }
}

class Dog extends Animal {}
class Cat extends Animal {} // Now Cat has a method it shouldn’t

    
}
