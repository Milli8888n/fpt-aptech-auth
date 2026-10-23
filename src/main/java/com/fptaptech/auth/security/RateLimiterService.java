package com.fptaptech.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class RateLimiterService {

    private static final int MAX_REGISTRATIONS_PER_HOUR = 10;
    private static final int MAX_FORGOT_PASSWORDS_PER_HOUR = 20;
    private static final long ONE_HOUR_SECONDS = 3600;

    private final Map<String, CopyOnWriteArrayList<Instant>> registrationAttempts = new ConcurrentHashMap<>();
    private final Map<String, CopyOnWriteArrayList<Instant>> forgotPasswordAttempts = new ConcurrentHashMap<>();

    public boolean allowRegistration(String ip) {
        return checkAndRecord(registrationAttempts, ip, MAX_REGISTRATIONS_PER_HOUR);
    }

    public boolean allowForgotPassword(String ip) {
        return checkAndRecord(forgotPasswordAttempts, ip, MAX_FORGOT_PASSWORDS_PER_HOUR);
    }

    private boolean checkAndRecord(Map<String, CopyOnWriteArrayList<Instant>> map, String ip, int maxAllowed) {
        if (ip == null || ip.isBlank()) return true;
        Instant now = Instant.now();
        Instant cutoff = now.minusSeconds(ONE_HOUR_SECONDS);

        CopyOnWriteArrayList<Instant> timestamps = map.computeIfAbsent(ip, k -> new CopyOnWriteArrayList<>());
        timestamps.removeIf(t -> t.isBefore(cutoff));

        if (timestamps.size() >= maxAllowed) {
            return false;
        }

        timestamps.add(now);
        return true;
    }

    public String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
