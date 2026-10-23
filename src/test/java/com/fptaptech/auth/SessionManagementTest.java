package com.fptaptech.auth;

import com.fptaptech.auth.service.SessionManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class SessionManagementTest {

    @Autowired
    private SessionManagementService sessionManagementService;

    @Autowired
    private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    @Test
    @DisplayName("F8: Giới hạn tối đa 2 phiên đồng thời - Đăng nhập phiên thứ 3 sẽ tự động hủy phiên cũ nhất")
    void testMax2ConcurrentSessionsLimit() {
        String testUser = "concurrent_user_test";

        // Create 3 sessions manually
        Session s1 = sessionRepository.createSession();
        s1.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, testUser);
        s1.setAttribute(SessionManagementService.ATTR_CLIENT_IP, "192.168.1.10");
        s1.setAttribute(SessionManagementService.ATTR_USER_AGENT, "Chrome on Windows");
        s1.setLastAccessedTime(Instant.now().minusSeconds(120)); // oldest
        ((FindByIndexNameSessionRepository<Session>) sessionRepository).save(s1);

        Session s2 = sessionRepository.createSession();
        s2.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, testUser);
        s2.setAttribute(SessionManagementService.ATTR_CLIENT_IP, "192.168.1.11");
        s2.setAttribute(SessionManagementService.ATTR_USER_AGENT, "Safari on iPhone");
        s2.setLastAccessedTime(Instant.now().minusSeconds(60));
        ((FindByIndexNameSessionRepository<Session>) sessionRepository).save(s2);

        Session s3 = sessionRepository.createSession();
        s3.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, testUser);
        s3.setAttribute(SessionManagementService.ATTR_CLIENT_IP, "192.168.1.12");
        s3.setAttribute(SessionManagementService.ATTR_USER_AGENT, "Firefox on Linux");
        s3.setLastAccessedTime(Instant.now()); // newest
        ((FindByIndexNameSessionRepository<Session>) sessionRepository).save(s3);

        // Before enforcement: 3 sessions
        Map<String, ? extends Session> sessionsBefore = sessionRepository.findByPrincipalName(testUser);
        assertEquals(3, sessionsBefore.size());

        // Enforce limit on current session s3
        sessionManagementService.enforceConcurrentSessionLimit(testUser, s3.getId());

        // After enforcement: s1 (oldest) should be revoked, leaving only s2 and s3
        Map<String, ? extends Session> sessionsAfter = sessionRepository.findByPrincipalName(testUser);
        assertEquals(2, sessionsAfter.size());
        assertNull(sessionRepository.findById(s1.getId()), "Phiên cũ nhất s1 phải bị hủy");
        assertNotNull(sessionRepository.findById(s2.getId()));
        assertNotNull(sessionRepository.findById(s3.getId()));
    }

    @Test
    @DisplayName("F8: Hủy phiên từ xa (Remote Revocation)")
    void testRemoteSessionRevocation() {
        String testUser = "remote_revoke_user";

        Session s1 = sessionRepository.createSession();
        s1.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, testUser);
        ((FindByIndexNameSessionRepository<Session>) sessionRepository).save(s1);

        assertNotNull(sessionRepository.findById(s1.getId()));

        sessionManagementService.revokeSession(s1.getId());

        assertNull(sessionRepository.findById(s1.getId()), "Phiên s1 phải bị xóa sau khi revokeSession");
    }
}
