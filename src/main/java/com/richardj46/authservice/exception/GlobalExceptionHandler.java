package com.richardj46.authservice.exception;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.ConstraintViolationException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodArgumentNotValid(
            MethodArgumentNotValidException exception
    ) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError fieldError : exception.getBindingResult().getFieldErrors()) {
            fieldErrors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }

        String message = fieldErrors.values().stream().findFirst().orElse("Validation failed");
        return ResponseEntity.badRequest().body(
                ApiErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Validation failed", message, fieldErrors)
        );
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleConstraintViolation(ConstraintViolationException exception) {
        Map<String, String> fieldErrors = exception.getConstraintViolations().stream()
                .collect(Collectors.toMap(
                        violation -> violation.getPropertyPath().toString(),
                        violation -> violation.getMessage(),
                        (first, ignored) -> first,
                        LinkedHashMap::new
                ));

        String message = fieldErrors.values().stream().findFirst().orElse("Validation failed");
        return ResponseEntity.badRequest().body(
                ApiErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Validation failed", message, fieldErrors)
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadableMessage(HttpMessageNotReadableException exception) {
        return ResponseEntity.badRequest().body(
                ApiErrorResponse.of(
                        HttpStatus.BAD_REQUEST.value(),
                        "Validation failed",
                        "Request body is missing or malformed"
                )
        );
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiErrorResponse> handleMissingParameter(
            MissingServletRequestParameterException exception
    ) {
        String message = exception.getParameterName() + " is required";
        return ResponseEntity.badRequest().body(
                ApiErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Validation failed", message)
        );
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiErrorResponse> handleTypeMismatch(MethodArgumentTypeMismatchException exception) {
        String message = exception.getName() + " has an invalid value";
        return ResponseEntity.badRequest().body(
                ApiErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Validation failed", message)
        );
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException exception
    ) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(
                ApiErrorResponse.of(
                        HttpStatus.METHOD_NOT_ALLOWED.value(),
                        "Method Not Allowed",
                        exception.getMessage() != null ? exception.getMessage() : "HTTP method not supported"
                )
        );
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiErrorResponse> handleResponseStatus(ResponseStatusException exception) {
        HttpStatus status = HttpStatus.valueOf(exception.getStatusCode().value());
        String message = exception.getReason() != null ? exception.getReason() : status.getReasonPhrase();
        return ResponseEntity.status(status).body(
                ApiErrorResponse.of(status.value(), status.getReasonPhrase(), message)
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                ApiErrorResponse.of(HttpStatus.FORBIDDEN.value(), "Forbidden", "Access denied")
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthentication(AuthenticationException exception) {
        if (exception instanceof LockedException) {
            return unauthorized("Account is temporarily locked");
        }
        if (exception instanceof DisabledException) {
            return unauthorized("User account is disabled");
        }
        return unauthorized("Invalid email or password");
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiErrorResponse> handleDataAccess(DataAccessException exception) {
        log.error("Database error", exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ApiErrorResponse.of(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "Internal Server Error",
                        "An unexpected error occurred"
                )
        );
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalState(IllegalStateException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ApiErrorResponse.of(
                        HttpStatus.CONFLICT.value(),
                        "Conflict",
                        exception.getMessage() != null ? exception.getMessage() : "Request conflicts with current state"
                )
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGeneric(Exception exception) {
        log.error("Unhandled error", exception);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ApiErrorResponse.of(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "Internal Server Error",
                        "An unexpected error occurred"
                )
        );
    }

    private static ResponseEntity<ApiErrorResponse> unauthorized(String message) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ApiErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", message)
        );
    }
}
