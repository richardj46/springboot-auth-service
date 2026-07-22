package com.richardj46.authservice.exception;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ApiErrorResponse(
        String timestamp,
        int status,
        String error,
        String message,
        Map<String, String> fieldErrors
) {

    public static ApiErrorResponse of(int status, String error, String message) {
        return new ApiErrorResponse(Instant.now().toString(), status, error, message, null);
    }

    public static ApiErrorResponse of(int status, String error, String message, Map<String, String> fieldErrors) {
        return new ApiErrorResponse(Instant.now().toString(), status, error, message, fieldErrors);
    }
}
