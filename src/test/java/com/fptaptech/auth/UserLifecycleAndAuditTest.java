package com.fptaptech.auth;

import com.fptaptech.auth.domain.*;
import com.fptaptech.auth.repository.*;
import com.fptaptech.auth.service.AdminService;
import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class UserLifecycleAndAuditTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AdminService adminService;

    @Autowired
    private UserService userService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private AppUser admin;

    @BeforeEach
    void setUp() {
        Role adminRole = roleRepository.findByName(Role.ADMIN)
            .orElseGet(() -> roleRepository.save(new Role(Role.ADMIN)));

        admin = userRepository.findByEmail("super_admin@fpt.edu.vn").orElseGet(() -> {
            AppUser u = new AppUser("super_admin@fpt.edu.vn", "super_admin", passwordEncoder.encode("AdminPass@2026!"), UserStatus.ACTIVE);
            u.getRoles().add(adminRole);
            return userRepository.save(u);
        });
    }

    @Test
    @DisplayName("Vòng đời tài khoản: Admin mời Giảng viên mới (INVITED) và kích hoạt thành công")
    void testInviteAndActivateLifecycle() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        // 1. Admin invites lecturer -> status INVITED
        AppUser invitedUser = adminService.inviteUser("gv_tuan@fpt.edu.vn", "gv_tuan", Role.LECTURER, request);
        assertEquals(UserStatus.INVITED, invitedUser.getStatus());
        assertTrue(invitedUser.hasRole(Role.LECTURER));

        // Create a specific known token for testing resetPassword
        String rawToken = "custom_test_invitation_token_123456";
        TokenEntity customToken = new TokenEntity(
            UserService.hashToken(rawToken),
            TokenType.INVITATION,
            invitedUser,
            java.time.Instant.now().plusSeconds(86400)
        );
        tokenRepository.save(customToken);

        // 2. Lecturer sets password via raw token -> status becomes ACTIVE
        String newPassword = "LecturerPassword#2026!";
        userService.resetPassword(rawToken, newPassword, request);

        AppUser activatedUser = userRepository.findById(invitedUser.getId()).orElseThrow();
        assertEquals(UserStatus.ACTIVE, activatedUser.getStatus());
        assertTrue(passwordEncoder.matches(newPassword, activatedUser.getPasswordHash()));
    }

    @Test
    @DisplayName("Vòng đời tài khoản: Chuyển ACTIVE -> DISABLED lập tức vô hiệu hóa tài khoản")
    void testDisableUserLifecycle() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Role studentRole = roleRepository.findByName(Role.STUDENT)
            .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));

        AppUser student = new AppUser("test_disable@fpt.edu.vn", "test_disable", passwordEncoder.encode("ValidPass#2026!"), UserStatus.ACTIVE);
        student.getRoles().add(studentRole);
        student = userRepository.save(student);

        // Disable user
        adminService.toggleDisableUser(student.getId(), admin.getId(), request);
        AppUser disabled = userRepository.findById(student.getId()).orElseThrow();
        assertEquals(UserStatus.DISABLED, disabled.getStatus());

        // Enable again
        adminService.toggleDisableUser(student.getId(), admin.getId(), request);
        AppUser reEnabled = userRepository.findById(student.getId()).orElseThrow();
        assertEquals(UserStatus.ACTIVE, reEnabled.getStatus());
    }

    @Test
    @DisplayName("F11: Nhật ký kiểm toán (Audit Logs) ghi nhận chính xác IP, hành động và trạng thái")
    void testAuditLogging() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.20.30.40");
        request.addHeader("User-Agent", "JUnit-Custom-Agent/1.0");

        auditService.logEvent("audit_user@fpt.edu.vn", "TEST_SECURITY_EVENT", "SUCCESS", "Kiểm thử lưu vết nhật ký", request);

        Page<AuditLogEntity> logs = auditService.getAuditLogs("audit_user@fpt.edu.vn", "TEST_SECURITY_EVENT", "SUCCESS", PageRequest.of(0, 10));
        assertFalse(logs.isEmpty());

        AuditLogEntity log = logs.getContent().get(0);
        assertEquals("10.20.30.40", log.getIpAddress());
        assertEquals("JUnit-Custom-Agent/1.0", log.getUserAgent());
        assertEquals("SUCCESS", log.getStatus());
        assertEquals("Kiểm thử lưu vết nhật ký", log.getDetails());
    }
}
