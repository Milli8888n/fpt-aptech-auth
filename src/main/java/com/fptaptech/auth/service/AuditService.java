package com.fptaptech.auth.service;

import com.fptaptech.auth.domain.AuditLogEntity;
import com.fptaptech.auth.repository.AuditLogRepository;
import com.fptaptech.auth.security.RateLimiterService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final RateLimiterService rateLimiterService;

    public AuditService(AuditLogRepository auditLogRepository, RateLimiterService rateLimiterService) {
        this.auditLogRepository = auditLogRepository;
        this.rateLimiterService = rateLimiterService;
    }

    @Transactional
    public void logEvent(String email, String action, String status, String details, HttpServletRequest request) {
        String ip = request != null ? rateLimiterService.extractClientIp(request) : "127.0.0.1";
        String userAgent = request != null ? request.getHeader("User-Agent") : "Internal";
        if (userAgent != null && userAgent.length() > 250) {
            userAgent = userAgent.substring(0, 250);
        }

        AuditLogEntity log = new AuditLogEntity(
            Instant.now(),
            email != null ? email : "anonymous",
            action,
            ip,
            userAgent,
            status,
            details
        );
        auditLogRepository.save(log);
    }

    @Transactional(readOnly = true)
    public Page<AuditLogEntity> getAuditLogs(String email, String action, String status, Pageable pageable) {
        return auditLogRepository.searchAuditLogs(email, action, status, pageable);
    }
}
