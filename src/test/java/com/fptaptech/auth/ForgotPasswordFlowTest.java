package com.fptaptech.auth;

import com.fptaptech.auth.domain.*;
import com.fptaptech.auth.repository.*;
import com.fptaptech.auth.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class ForgotPasswordFlowTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private AppUser testUser;
    private static final String INITIAL_PASS = "InitialComplexPass#2026";

    @BeforeEach
    void setUp() {
        Role studentRole = roleRepository.findByName(Role.STUDENT)
            .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));

        testUser = userRepository.findByEmail("forgot_tester@fpt.edu.vn").orElseGet(() -> {
            AppUser u = new AppUser("forgot_tester@fpt.edu.vn", "forgot_tester", passwordEncoder.encode(INITIAL_PASS), UserStatus.ACTIVE);
            u.getRoles().add(studentRole);
            return userRepository.save(u);
        });
    }

    @Test
    @DisplayName("F3: Quên mật khẩu - Phản hồi mờ (Blind Response) không ném lỗi dù email không tồn tại")
    void testBlindResponseForNonExistentEmail() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertDoesNotThrow(() ->
            userService.forgotPassword("random_ghost_email_999@fpt.edu.vn", request)
        );
    }

    @Test
    @DisplayName("F3: Đặt lại mật khẩu thành công qua Token hợp lệ")
    void testResetPasswordWithValidToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        String rawToken = "secure_reset_token_test_123456";
        TokenEntity token = new TokenEntity(
            UserService.hashToken(rawToken),
            TokenType.PASSWORD_RESET,
            testUser,
            Instant.now().plusSeconds(1800) // 30 mins
        );
        tokenRepository.save(token);

        String newPassword = "BrandNewSecurePassword#2026!";
        userService.resetPassword(rawToken, newPassword, request);

        AppUser updated = userRepository.findById(testUser.getId()).orElseThrow();
        assertTrue(passwordEncoder.matches(newPassword, updated.getPasswordHash()));

        // Token should now be marked as used
        TokenEntity updatedToken = tokenRepository.findById(token.getId()).orElseThrow();
        assertTrue(updatedToken.isUsed());
    }

    @Test
    @DisplayName("F3: Từ chối đặt lại mật khẩu khi tái sử dụng token đã dùng")
    void testRejectReusedToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        String rawToken = "already_used_token_123456";
        TokenEntity token = new TokenEntity(
            UserService.hashToken(rawToken),
            TokenType.PASSWORD_RESET,
            testUser,
            Instant.now().plusSeconds(1800)
        );
        token.setUsedAt(Instant.now()); // Already used
        tokenRepository.save(token);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            userService.resetPassword(rawToken, "AnotherPassword#2026!", request)
        );
        assertTrue(ex.getMessage().contains("đã được sử dụng"));
    }

    @Test
    @DisplayName("F3: Từ chối đặt lại mật khẩu khi token đã hết hạn")
    void testRejectExpiredToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        String rawToken = "expired_token_123456";
        TokenEntity token = new TokenEntity(
            UserService.hashToken(rawToken),
            TokenType.PASSWORD_RESET,
            testUser,
            Instant.now().minusSeconds(10) // Expired 10 seconds ago
        );
        tokenRepository.save(token);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            userService.resetPassword(rawToken, "AnotherPassword#2026!", request)
        );
        assertTrue(ex.getMessage().contains("đã hết hạn"));
    }
}
