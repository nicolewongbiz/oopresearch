package com.nicole;

public class inside extends RedundantOverride {
    @Override
    void speak() {
        System.out.println("Animal speaks"); // Redundant override - same as parent
    }
}
