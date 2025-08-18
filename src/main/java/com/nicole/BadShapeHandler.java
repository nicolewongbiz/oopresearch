package com.nicole;

public class BadShapeHandler {
    private ShapeType type;

    public BadShapeHandler(ShapeType type) {
        this.type = type;
    }

    // Case 1: Enum comparison with if/else
    public void drawIfElse() {
        if (type == ShapeType.CIRCLE) {
            System.out.println("Drawing a circle");
        } else if (type == ShapeType.SQUARE) {
            System.out.println("Drawing a square");
        } else if (type.equals(ShapeType.TRIANGLE)) {
            System.out.println("Drawing a triangle");
        }
    }

    // Case 2: Switch on enum
    public void drawSwitch() {
        switch (type) {
            case CIRCLE:
                System.out.println("Drawing a circle");
                break;
            case SQUARE:
                System.out.println("Drawing a square");
                break;
            case TRIANGLE:
                System.out.println("Drawing a triangle");
                break;
        }
    }
}
