package com.ghost.detect;

public class MalformedRequestException extends DetectionException {
    public MalformedRequestException(String message) {
        super(400, message);
    }
}
