package com.fptaptech.auth;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.Role;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.RoleRepository;
import com.fptaptech.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountLockoutTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String TEST_USER = "lockout_victim";
    private static final String CORRECT_PASS = "ValidPassword123#";

    @BeforeEach
    void setUp() {
        userRepository.findByUsername(TEST_USER).ifPresent(userRepository::delete);

        Role role = roleRepository.findByName(Role.STUDENT)
            .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));

        AppUser user = new AppUser("victim@fpt.edu.vn", TEST_USER, passwordEncoder.encode(CORRECT_PASS), UserStatus.ACTIVE);
        user.getRoles().add(role);
        userRepository.save(user);
    }

    @Test
    @DisplayName("F5: Nhập sai mật khẩu 5 lần liên tiếp sẽ bị khóa tài khoản 15 phút")
    void testAccountLockoutAfter5FailedAttempts() throws Exception {
        // 4 failed attempts
        for (int i = 1; i <= 4; i++) {
            mvc.perform(post("/login").with(csrf())
                    .param("username", TEST_USER)
                    .param("password", "wrong_password_" + i))
                .andExpect(redirectedUrl("/login?error=true"));

            AppUser user = userRepository.findByUsername(TEST_USER).orElseThrow();
            assertEquals(i, user.getFailedAttempts());
            assertEquals(UserStatus.ACTIVE, user.getStatus());
        }

        // 5th failed attempt -> account locked
        mvc.perform(post("/login").with(csrf())
                .param("username", TEST_USER)
                .param("password", "wrong_password_5"))
            .andExpect(redirectedUrl("/login?locked=true"));

        AppUser lockedUser = userRepository.findByUsername(TEST_USER).orElseThrow();
        assertEquals(5, lockedUser.getFailedAttempts());
        assertEquals(UserStatus.LOCKED, lockedUser.getStatus());
        assertNotNull(lockedUser.getLockedUntil());
    }

    @Test
    @DisplayName("F5 & An ninh: Chống Timing Attack - Độ lệch thời gian giữa username không tồn tại và sai password <= 50ms")
    void testTimingAttackDefense() throws Exception {
        // Reset TEST_USER to ACTIVE and 0 attempts
        AppUser resetUser = userRepository.findByUsername(TEST_USER).orElseThrow();
        resetUser.setFailedAttempts(0);
        resetUser.setStatus(UserStatus.ACTIVE);
        resetUser.setLockedUntil(null);
        userRepository.save(resetUser);

        // Warm up JIT compiler on both authentication paths
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/login").with(csrf())
                .param("username", "ghost_user_" + i)
                .param("password", "some_password_123#"));
            mvc.perform(post("/login").with(csrf())
                .param("username", TEST_USER)
                .param("password", "some_password_123#"));
            // Keep attempts < 5
            resetUser.setFailedAttempts(0);
            userRepository.save(resetUser);
        }

        // Measure average time over 3 requests for non-existent user
        long totalNonExistent = 0;
        for (int i = 0; i < 3; i++) {
            long start = System.nanoTime();
            mvc.perform(post("/login").with(csrf())
                .param("username", "non_existent_account_" + i)
                .param("password", "wrong_password_test#"));
            totalNonExistent += (System.nanoTime() - start) / 1_000_000;
        }
        long avgNonExistent = totalNonExistent / 3;

        // Measure average time over 3 requests for real user with wrong password
        long totalReal = 0;
        for (int i = 0; i < 3; i++) {
            resetUser.setFailedAttempts(0);
            userRepository.save(resetUser);

            long start = System.nanoTime();
            mvc.perform(post("/login").with(csrf())
                .param("username", TEST_USER)
                .param("password", "wrong_password_test#"));
            totalReal += (System.nanoTime() - start) / 1_000_000;
        }
        long avgReal = totalReal / 3;

        long delta = Math.abs(avgNonExistent - avgReal);
        assertTrue(delta <= 50, "Độ lệch thời gian phản hồi trung bình (" + delta + "ms) phải <= 50ms để chống Timing Attack");
    }
}
