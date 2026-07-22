package com.richardj46.authservice.audit;

import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists security audit events and emits structured application logs.
 */
@Service
public class AuditService {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY_AUDIT");

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(
            AuditEventType eventType,
            UUID userId,
            String email,
            HttpServletRequest request,
            String details
    ) {
        String ipAddress = request != null ? clientIp(request) : null;
        String userAgent = request != null ? truncate(request.getHeader("User-Agent"), 512) : null;
        String safeDetails = truncate(details, 512);

        AuditLog auditLog = new AuditLog();
        auditLog.setEventType(eventType);
        auditLog.setUserId(userId);
        auditLog.setEmail(email);
        auditLog.setIpAddress(ipAddress);
        auditLog.setUserAgent(userAgent);
        auditLog.setDetails(safeDetails);
        auditLogRepository.save(auditLog);

        writeSecurityLog(eventType, userId, email, ipAddress, safeDetails);
    }

    private void writeSecurityLog(
            AuditEventType eventType,
            UUID userId,
            String email,
            String ipAddress,
            String details
    ) {
        String message = "event={} userId={} email={} ip={} details={}";
        Object[] args = {
                eventType.name(),
                userId != null ? userId : "-",
                email != null ? email : "-",
                ipAddress != null ? ipAddress : "-",
                details != null ? details : "-"
        };

        if (eventType.isFailure()) {
            securityLog.warn(message, args);
        } else {
            securityLog.info(message, args);
        }
    }

    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }
}
