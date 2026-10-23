package com.fptaptech.auth;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.PasswordHistoryEntity;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.PasswordHistoryRepository;
import com.fptaptech.auth.service.PasswordPolicyValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordPolicyTest {

    @Mock
    private PasswordHistoryRepository passwordHistoryRepository;

    private PasswordPolicyValidator validator;
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setUp() throws Exception {
        validator = new PasswordPolicyValidator(passwordHistoryRepository);
        Method loadMethod = PasswordPolicyValidator.class.getDeclaredMethod("loadCommonPasswords");
        loadMethod.setAccessible(true);
        loadMethod.invoke(validator);
    }

    @Test
    @DisplayName("F4: Mật khẩu dưới 12 ký tự bị từ chối")
    void testPasswordTooShort() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            validator.validateNewPassword("ShortPass1!", "user1", "user1@fpt.edu.vn", null, encoder)
        );
        assertTrue(ex.getMessage().contains("tối thiểu 12 ký tự"));
    }

    @Test
    @DisplayName("F4: Mật khẩu chứa tên đăng nhập bị từ chối")
    void testPasswordContainsUsername() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            validator.validateNewPassword("NguyenVanAn@2026", "nguyenvanan", "an@fpt.edu.vn", null, encoder)
        );
        assertTrue(ex.getMessage().contains("tên đăng nhập"));
    }

    @Test
    @DisplayName("F4: Mật khẩu chứa phần local part của email bị từ chối")
    void testPasswordContainsEmailLocalPart() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            validator.validateNewPassword("SecurePass_hoangtam2026", "user99", "hoangtam@fpt.edu.vn", null, encoder)
        );
        assertTrue(ex.getMessage().contains("địa chỉ email"));
    }

    @Test
    @DisplayName("F4: Mật khẩu nằm trong danh sách 10.000 từ điển phổ biến bị từ chối")
    void testPasswordInBlacklist() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            validator.validateNewPassword("fptaptech2026", "student1", "student1@fpt.edu.vn", null, encoder)
        );
        assertTrue(ex.getMessage().contains("quá phổ biến"));
    }

    @Test
    @DisplayName("F4: Mật khẩu trùng với 1 trong 5 mật khẩu gần nhất bị từ chối")
    void testPasswordInLast5History() {
        AppUser dummyUser = new AppUser("user@fpt.edu.vn", "user", "hash", UserStatus.ACTIVE);
        String oldPass = "VeryComplexPassword#2026";
        String oldHash = encoder.encode(oldPass);

        when(passwordHistoryRepository.findTop5ByUserIdOrderByCreatedAtDesc(1L))
            .thenReturn(List.of(new PasswordHistoryEntity(dummyUser, oldHash)));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
            validator.validateNewPassword(oldPass, "user", "user@fpt.edu.vn", 1L, encoder)
        );
        assertTrue(ex.getMessage().contains("5 mật khẩu gần nhất"));
    }

    @Test
    @DisplayName("F4: Mật khẩu thỏa mãn đầy đủ tiêu chuẩn được chấp nhận")
    void testValidPassword() {
        assertDoesNotThrow(() ->
            validator.validateNewPassword("StrongSecret#Key2026!", "john_doe", "john@fpt.edu.vn", null, encoder)
        );
    }
}
