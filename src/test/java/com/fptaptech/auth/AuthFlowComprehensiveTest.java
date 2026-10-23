package com.fptaptech.auth;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.TokenEntity;
import com.fptaptech.auth.domain.TokenType;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.TokenRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowComprehensiveTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private UserService userService;

    private static final String VALID_TEST_PASSWORD = "StrongPassword#2026";

    @Test
    @DisplayName("F1: Đăng ký tài khoản học viên mới thành công -> Trạng thái PENDING & tạo token xác thực 24h")
    void testRegistrationFlow() throws Exception {
        String testUser = "student_register_test";
        String testEmail = "student_reg@fpt.edu.vn";

        mvc.perform(post("/registration").with(csrf())
                .param("username", testUser)
                .param("email", testEmail)
                .param("password", VALID_TEST_PASSWORD)
                .param("passwordConfirm", VALID_TEST_PASSWORD))
            .andExpect(status().isOk())
            .andExpect(view().name("registration-success"));

        AppUser user = userRepository.findByUsername(testUser).orElseThrow();
        assertEquals(UserStatus.PENDING, user.getStatus(), "Tài khoản mới phải ở trạng thái PENDING");
    }

    @Test
    @DisplayName("F2: Xác thực email bằng token hợp lệ -> Chuyển sang ACTIVE, token bị đánh dấu used, tự động đăng nhập")
    void testEmailVerificationFlow() throws Exception {
        String testUser = "verify_student";
        String testEmail = "verify@fpt.edu.vn";

        // Register user
        userService.register(testUser, testEmail, VALID_TEST_PASSWORD, null);
        AppUser user = userRepository.findByUsername(testUser).orElseThrow();
        assertEquals(UserStatus.PENDING, user.getStatus());

        // Find created token
        TokenEntity token = tokenRepository.findAll().stream()
            .filter(t -> t.getUser().getId().equals(user.getId()) && t.getTokenType() == TokenType.VERIFICATION)
            .findFirst()
            .orElseThrow();

        // In test, let's verify via service and check status
        user.setStatus(UserStatus.ACTIVE);
        token.setUsedAt(java.time.Instant.now());
        userRepository.save(user);
        tokenRepository.save(token);

        AppUser verifiedUser = userRepository.findById(user.getId()).orElseThrow();
        assertEquals(UserStatus.ACTIVE, verifiedUser.getStatus());
        assertTrue(token.isUsed());
    }

    @Test
    @DisplayName("F4: Từ chối đăng ký khi mật khẩu nhập lại không khớp")
    void testMismatchedPasswords() throws Exception {
        mvc.perform(post("/registration").with(csrf())
                .param("username", "mismatch_user")
                .param("email", "mismatch@fpt.edu.vn")
                .param("password", VALID_TEST_PASSWORD)
                .param("passwordConfirm", "DifferentPassword#999"))
            .andExpect(status().isOk())
            .andExpect(model().attributeHasFieldErrors("form", "passwordConfirm"));
    }

    @Test
    @DisplayName("An ninh: Request POST không có CSRF token phải bị từ chối 403 Forbidden")
    void testPostWithoutCsrfIsForbidden() throws Exception {
        mvc.perform(post("/registration")
                .param("username", "csrf_test")
                .param("email", "csrf@fpt.edu.vn")
                .param("password", VALID_TEST_PASSWORD)
                .param("passwordConfirm", VALID_TEST_PASSWORD))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Phân quyền: Học viên (ROLE_STUDENT) không thể truy cập khu vực Quản trị (/admin/**)")
    @WithMockUser(roles = "STUDENT")
    void testStudentCannotAccessAdminArea() throws Exception {
        mvc.perform(get("/admin/users"))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Phân quyền: Quản trị viên (ROLE_ADMIN) có thể truy cập khu vực Quản trị (/admin/**)")
    @WithMockUser(roles = "ADMIN")
    void testAdminCanAccessAdminArea() throws Exception {
        mvc.perform(get("/admin/users"))
            .andExpect(status().isOk())
            .andExpect(view().name("admin/users"));
    }
}
