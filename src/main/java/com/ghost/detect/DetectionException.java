package com.ghost.detect;

public abstract class DetectionException extends RuntimeException {
    private final int httpStatus;

    protected DetectionException(int httpStatus, String message) {
        super(message);
        this.httpStatus = httpStatus;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
