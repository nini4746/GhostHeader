package com.ghost.web;

import com.ghost.detect.DetectionException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Map;

@ControllerAdvice
public class DetectionExceptionHandler {

    @ExceptionHandler(DetectionException.class)
    public ResponseEntity<Map<String, Object>> handle(DetectionException e) {
        HttpStatus status = HttpStatus.valueOf(e.httpStatus());
        return ResponseEntity.status(status).body(Map.of(
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "message", e.getMessage() == null ? "" : e.getMessage()
        ));
    }
}
