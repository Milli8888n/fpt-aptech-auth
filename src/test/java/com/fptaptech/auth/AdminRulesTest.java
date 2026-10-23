package com.fptaptech.auth;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.Role;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.RoleRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AdminRulesTest {

    @Autowired
    private AdminService adminService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private AppUser admin1;
    private AppUser admin2;
    private AppUser student;

    @BeforeEach
    void setUp() {
        Role adminRole = roleRepository.findByName(Role.ADMIN)
            .orElseGet(() -> roleRepository.save(new Role(Role.ADMIN)));
        Role studentRole = roleRepository.findByName(Role.STUDENT)
            .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));

        admin1 = userRepository.findByEmail("admin1_test@fpt.edu.vn").orElseGet(() -> {
            AppUser u = new AppUser("admin1_test@fpt.edu.vn", "admin1_test", passwordEncoder.encode("Pass#123456789"), UserStatus.ACTIVE);
            u.getRoles().add(adminRole);
            return userRepository.save(u);
        });

        admin2 = userRepository.findByEmail("admin2_test@fpt.edu.vn").orElseGet(() -> {
            AppUser u = new AppUser("admin2_test@fpt.edu.vn", "admin2_test", passwordEncoder.encode("Pass#123456789"), UserStatus.ACTIVE);
            u.getRoles().add(adminRole);
            return userRepository.save(u);
        });

        student = userRepository.findByEmail("student_test@fpt.edu.vn").orElseGet(() -> {
            AppUser u = new AppUser("student_test@fpt.edu.vn", "student_test", passwordEncoder.encode("Pass#123456789"), UserStatus.ACTIVE);
            u.getRoles().add(studentRole);
            return userRepository.save(u);
        });
    }

    @Test
    @DisplayName("F10: Chặn Admin tự vô hiệu hóa tài khoản của chính mình")
    void testAdminCannotSelfDisable() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
            adminService.toggleDisableUser(admin1.getId(), admin1.getId(), request)
        );
        assertTrue(ex.getMessage().contains("tự vô hiệu hóa"));
    }

    @Test
    @DisplayName("F10: Chặn Admin tự gỡ quyền Admin của chính mình")
    void testAdminCannotSelfDemote() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
            adminService.changeRole(admin1.getId(), Role.STUDENT, admin1.getId(), request)
        );
        assertTrue(ex.getMessage().contains("tự gỡ quyền"));
    }

    @Test
    @DisplayName("F10: Cho phép Admin thay đổi vai trò hoặc khóa/mở khóa tài khoản học viên")
    void testAdminCanManageStudent() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        // Lock student
        adminService.lockUser(student.getId(), request);
        AppUser lockedStudent = userRepository.findById(student.getId()).orElseThrow();
        assertEquals(UserStatus.LOCKED, lockedStudent.getStatus());

        // Unlock student
        adminService.unlockUser(student.getId(), request);
        AppUser unlockedStudent = userRepository.findById(student.getId()).orElseThrow();
        assertEquals(UserStatus.ACTIVE, unlockedStudent.getStatus());

        // Change role to LECTURER
        adminService.changeRole(student.getId(), Role.LECTURER, admin1.getId(), request);
        AppUser lecturerStudent = userRepository.findById(student.getId()).orElseThrow();
        assertTrue(lecturerStudent.hasRole(Role.LECTURER));
    }
}
