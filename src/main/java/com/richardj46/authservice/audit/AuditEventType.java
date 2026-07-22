package com.richardj46.authservice.audit;

public enum AuditEventType {
    REGISTER,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGIN_LOCKED,
    LOGOUT,
    TOKEN_REFRESH,
    PASSWORD_CHANGE,
    ACCOUNT_DISABLE,
    ACCOUNT_DELETE,
    ADMIN_USER_UPDATE,
    ADMIN_USER_DELETE,
    ADMIN_PASSWORD_RESET;

    public boolean isFailure() {
        return this == LOGIN_FAILURE || this == LOGIN_LOCKED;
    }
}
