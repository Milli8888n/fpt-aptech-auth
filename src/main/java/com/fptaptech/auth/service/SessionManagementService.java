package com.fptaptech.auth.service;

import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

@Service
public class SessionManagementService {

    public static final String ATTR_CLIENT_IP = "CLIENT_IP";
    public static final String ATTR_USER_AGENT = "USER_AGENT";

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    public SessionManagementService(FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public static class ActiveSessionDto {
        private final String sessionId;
        private final Instant creationTime;
        private final Instant lastAccessTime;
        private final String ipAddress;
        private final String userAgent;
        private final boolean current;

        public ActiveSessionDto(String sessionId, Instant creationTime, Instant lastAccessTime, String ipAddress, String userAgent, boolean current) {
            this.sessionId = sessionId;
            this.creationTime = creationTime;
            this.lastAccessTime = lastAccessTime;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.current = current;
        }

        public String getSessionId() { return sessionId; }
        public Instant getCreationTime() { return creationTime; }
        public Instant getLastAccessTime() { return lastAccessTime; }
        public String getIpAddress() { return ipAddress; }
        public String getUserAgent() { return userAgent; }
        public boolean isCurrent() { return current; }
    }

    public List<ActiveSessionDto> getUserSessions(String username, String currentSessionId) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
        List<ActiveSessionDto> dtos = new ArrayList<>();

        for (Map.Entry<String, ? extends Session> entry : sessions.entrySet()) {
            Session session = entry.getValue();
            String id = session.getId();
            Instant creation = session.getCreationTime();
            Instant lastAccess = session.getLastAccessedTime();
            String ip = session.getAttribute(ATTR_CLIENT_IP);
            String ua = session.getAttribute(ATTR_USER_AGENT);

            dtos.add(new ActiveSessionDto(
                id,
                creation,
                lastAccess,
                ip != null ? ip : "Không xác định",
                ua != null ? ua : "Không xác định",
                id.equals(currentSessionId)
            ));
        }

        dtos.sort(Comparator.comparing(ActiveSessionDto::getLastAccessTime).reversed());
        return dtos;
    }

    public void revokeSession(String sessionId) {
        sessionRepository.deleteById(sessionId);
    }

    public void revokeAllUserSessions(String username) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
        for (String id : sessions.keySet()) {
            sessionRepository.deleteById(id);
        }
    }

    public void revokeAllOtherUserSessions(String username, String keepSessionId) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
        for (String id : sessions.keySet()) {
            if (!id.equals(keepSessionId)) {
                sessionRepository.deleteById(id);
            }
        }
    }

    /**
     * Enforces the max 2 concurrent sessions limit by terminating the oldest session if count >= 2.
     */
    public void enforceConcurrentSessionLimit(String username, String currentSessionId) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
        if (sessions.size() > 2) {
            // Find oldest session that is not the current one
            sessions.values().stream()
                .filter(s -> !s.getId().equals(currentSessionId))
                .min(Comparator.comparing(Session::getLastAccessedTime))
                .ifPresent(oldest -> sessionRepository.deleteById(oldest.getId()));
        }
    }
}
