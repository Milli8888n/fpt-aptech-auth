package com.fptaptech.auth.service;

import com.fptaptech.auth.domain.*;
import com.fptaptech.auth.repository.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;

@Service
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final SessionManagementService sessionManagementService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final SecureRandom secureRandom = new SecureRandom();

    public AdminService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            TokenRepository tokenRepository,
            SessionManagementService sessionManagementService,
            EmailService emailService,
            AuditService auditService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.tokenRepository = tokenRepository;
        this.sessionManagementService = sessionManagementService;
        this.emailService = emailService;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public Page<AppUser> searchUsers(String query, String role, UserStatus status, Pageable pageable) {
        return userRepository.searchUsers(query, role, status, pageable);
    }

    @Transactional
    public void lockUser(Long userId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        user.setStatus(UserStatus.LOCKED);
        userRepository.save(user);

        auditService.logEvent(user.getEmail(), "ADMIN_LOCK_USER", "SUCCESS", "Quản trị viên khóa tài khoản", request);
    }

    @Transactional
    public void unlockUser(Long userId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        user.setStatus(UserStatus.ACTIVE);
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        auditService.logEvent(user.getEmail(), "ADMIN_UNLOCK_USER", "SUCCESS", "Quản trị viên mở khóa tài khoản", request);
    }

    @Transactional
    public void toggleDisableUser(Long userId, Long currentAdminId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (user.getId().equals(currentAdminId)) {
            throw new IllegalStateException("Quản trị viên không thể tự vô hiệu hóa tài khoản của chính mình");
        }

        if (user.hasRole(Role.ADMIN) && user.getStatus() == UserStatus.ACTIVE) {
            long activeAdminCount = userRepository.countByRoleNameAndStatus(Role.ADMIN, UserStatus.ACTIVE);
            if (activeAdminCount <= 1) {
                throw new IllegalStateException("Hệ thống luôn phải còn ít nhất 1 Quản trị viên đang hoạt động");
            }
        }

        if (user.getStatus() == UserStatus.DISABLED) {
            user.setStatus(UserStatus.ACTIVE);
            auditService.logEvent(user.getEmail(), "ADMIN_ENABLE_USER", "SUCCESS", "Kích hoạt lại tài khoản", request);
        } else {
            user.setStatus(UserStatus.DISABLED);
            // Invalidate all active sessions immediately
            sessionManagementService.revokeAllUserSessions(user.getUsername());
            auditService.logEvent(user.getEmail(), "ADMIN_DISABLE_USER", "SUCCESS", "Vô hiệu hóa tài khoản và hủy toàn bộ phiên", request);
        }
        userRepository.save(user);
    }

    @Transactional
    public void changeRole(Long userId, String newRoleName, Long currentAdminId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        if (user.getId().equals(currentAdminId) && !Role.ADMIN.equals(newRoleName)) {
            throw new IllegalStateException("Quản trị viên không thể tự gỡ quyền Quản trị viên của chính mình");
        }

        if (user.hasRole(Role.ADMIN) && !Role.ADMIN.equals(newRoleName) && user.getStatus() == UserStatus.ACTIVE) {
            long activeAdminCount = userRepository.countByRoleNameAndStatus(Role.ADMIN, UserStatus.ACTIVE);
            if (activeAdminCount <= 1) {
                throw new IllegalStateException("Hệ thống luôn phải còn ít nhất 1 Quản trị viên đang hoạt động");
            }
        }

        Role role = roleRepository.findByName(newRoleName)
            .orElseGet(() -> roleRepository.save(new Role(newRoleName)));

        user.getRoles().clear();
        user.getRoles().add(role);
        userRepository.save(user);

        auditService.logEvent(user.getEmail(), "ADMIN_CHANGE_ROLE", "SUCCESS", "Đổi vai trò thành: " + newRoleName, request);
    }

    @Transactional
    public void forceLogout(Long userId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng"));

        sessionManagementService.revokeAllUserSessions(user.getUsername());
        auditService.logEvent(user.getEmail(), "ADMIN_FORCE_LOGOUT", "SUCCESS", "Quản trị viên buộc đăng xuất toàn bộ phiên", request);
    }

    @Transactional
    public AppUser inviteUser(String email, String username, String roleName, HttpServletRequest request) {
        String normEmail = email.trim().toLowerCase(Locale.ROOT);
        String normUsername = username.trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByEmail(normEmail)) {
            throw new IllegalArgumentException("Email này đã được sử dụng");
        }
        if (userRepository.existsByUsername(normUsername)) {
            throw new IllegalArgumentException("Username này đã được sử dụng");
        }

        Role role = roleRepository.findByName(roleName)
            .orElseGet(() -> roleRepository.save(new Role(roleName)));

        // Unusable placeholder hash until user sets their password via invitation link
        String placeholderHash = "{bcrypt}$2a$10$INVITED_PLACEHOLDER_HASH_WILL_BE_SET_BY_USER_LINK";
        AppUser user = new AppUser(normEmail, normUsername, placeholderHash, UserStatus.INVITED);
        user.getRoles().add(role);
        user = userRepository.save(user);

        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        TokenEntity token = new TokenEntity(
            UserService.hashToken(rawToken),
            TokenType.INVITATION,
            user,
            Instant.now().plusSeconds(86400) // 24 hours
        );
        tokenRepository.save(token);

        emailService.sendInvitationEmail(normEmail, roleName, rawToken);
        auditService.logEvent(normEmail, "ADMIN_INVITE_USER", "SUCCESS", "Mời người dùng với vai trò " + roleName, request);

        return user;
    }
}
