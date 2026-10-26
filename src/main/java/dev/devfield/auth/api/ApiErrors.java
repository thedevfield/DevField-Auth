package dev.devfield.auth.api;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(ApiError.class)
    ResponseEntity<?> api(ApiError error) {
        return ResponseEntity.status(error.status()).body(java.util.Map.of("code", error.code()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<?> malformed() {
        return ResponseEntity.badRequest().body(java.util.Map.of("code", "invalid_request"));
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<?> storage() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(java.util.Map.of("code", "auth_unavailable"));
    }
}
