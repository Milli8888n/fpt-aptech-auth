package com.fptaptech.auth.service;

import com.fptaptech.auth.domain.*;
import com.fptaptech.auth.repository.*;
import com.fptaptech.auth.security.CustomAuthenticationSuccessHandler;
import com.fptaptech.auth.security.SecurityUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final AuditService auditService;
    private final SessionManagementService sessionManagementService;

    private final SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();
    private final SecureRandom secureRandom = new SecureRandom();

    public UserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            TokenRepository tokenRepository,
            PasswordHistoryRepository passwordHistoryRepository,
            PasswordPolicyValidator passwordPolicyValidator,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            AuditService auditService,
            SessionManagementService sessionManagementService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.tokenRepository = tokenRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.passwordPolicyValidator = passwordPolicyValidator;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.auditService = auditService;
        this.sessionManagementService = sessionManagementService;
    }

    public static String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Transactional
    public AppUser register(String username, String email, String rawPassword, HttpServletRequest request) {
        String normUsername = username.trim().toLowerCase(Locale.ROOT);
        String normEmail = email.trim().toLowerCase(Locale.ROOT);

        if (userRepository.existsByUsername(normUsername)) {
            throw new IllegalArgumentException("Username này đã được sử dụng");
        }
        if (userRepository.existsByEmail(normEmail)) {
            throw new IllegalArgumentException("Email này đã được sử dụng");
        }

        passwordPolicyValidator.validateNewPassword(rawPassword, normUsername, normEmail, null, passwordEncoder);

        Role studentRole = roleRepository.findByName(Role.STUDENT)
            .orElseGet(() -> roleRepository.save(new Role(Role.STUDENT)));

        AppUser user = new AppUser(normEmail, normUsername, passwordEncoder.encode(rawPassword), UserStatus.PENDING);
        user.getRoles().add(studentRole);
        user = userRepository.save(user);

        // Record initial password in history
        passwordHistoryRepository.save(new PasswordHistoryEntity(user, user.getPasswordHash()));

        // Create 24h verification token
        String rawToken = generateSecureToken();
        TokenEntity token = new TokenEntity(
            hashToken(rawToken),
            TokenType.VERIFICATION,
            user,
            Instant.now().plusSeconds(86400) // 24 hours
        );
        tokenRepository.save(token);

        emailService.sendVerificationEmail(normEmail, rawToken);
        auditService.logEvent(normEmail, "USER_REGISTERED", "SUCCESS", "Đăng ký tài khoản học viên mới (PENDING)", request);

        return user;
    }

    @Transactional
    public AppUser verifyEmail(String rawToken, HttpServletRequest request, HttpServletResponse response) {
        String hashed = hashToken(rawToken);
        TokenEntity token = tokenRepository.findByTokenHashAndTokenType(hashed, TokenType.VERIFICATION)
            .orElseThrow(() -> new IllegalArgumentException("Liên kết xác thực không hợp lệ"));

        if (token.isUsed()) {
            throw new IllegalArgumentException("Liên kết xác thực này đã được sử dụng");
        }
        if (token.isExpired()) {
            throw new IllegalArgumentException("Liên kết xác thực đã hết hạn (24 giờ)");
        }

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        AppUser user = token.getUser();
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        auditService.logEvent(user.getEmail(), "EMAIL_VERIFIED", "SUCCESS", "Xác thực email thành công, tài khoản kích hoạt ACTIVE", request);

        // Auto login
        autoLogin(user, request, response);

        return user;
    }

    @Transactional
    public void resendVerificationEmail(String email, HttpServletRequest request) {
        String normEmail = email.trim().toLowerCase(Locale.ROOT);
        AppUser user = userRepository.findByEmail(normEmail).orElse(null);

        if (user != null && user.getStatus() == UserStatus.PENDING) {
            Instant oneHourAgo = Instant.now().minusSeconds(3600);
            long recentCount = tokenRepository.countRecentTokens(user.getId(), TokenType.VERIFICATION, oneHourAgo);

            if (recentCount >= 3) {
                throw new IllegalStateException("Bạn đã gửi lại link xác thực 3 lần trong giờ qua. Vui lòng thử lại sau.");
            }

            String rawToken = generateSecureToken();
            TokenEntity token = new TokenEntity(
                hashToken(rawToken),
                TokenType.VERIFICATION,
                user,
                Instant.now().plusSeconds(86400)
            );
            tokenRepository.save(token);
            emailService.sendVerificationEmail(normEmail, rawToken);
            auditService.logEvent(normEmail, "RESEND_VERIFICATION", "SUCCESS", "Gửi lại link xác thực email", request);
        }
    }

    @Transactional
    public void forgotPassword(String email, HttpServletRequest request) {
        String normEmail = email.trim().toLowerCase(Locale.ROOT);
        AppUser user = userRepository.findByEmail(normEmail).orElse(null);

        if (user != null && user.getStatus() == UserStatus.ACTIVE) {
            String rawToken = generateSecureToken();
            TokenEntity token = new TokenEntity(
                hashToken(rawToken),
                TokenType.PASSWORD_RESET,
                user,
                Instant.now().plusSeconds(1800) // 30 minutes
            );
            tokenRepository.save(token);
            emailService.sendPasswordResetEmail(normEmail, rawToken);
            auditService.logEvent(normEmail, "FORGOT_PASSWORD_REQUEST", "SUCCESS", "Yêu cầu đặt lại mật khẩu", request);
        } else {
            auditService.logEvent(normEmail, "FORGOT_PASSWORD_REQUEST", "SUCCESS", "Yêu cầu đặt lại mật khẩu (Blind response)", request);
        }
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword, HttpServletRequest request) {
        String hashed = hashToken(rawToken);

        TokenEntity token = tokenRepository.findByTokenHashAndTokenType(hashed, TokenType.PASSWORD_RESET)
            .or(() -> tokenRepository.findByTokenHashAndTokenType(hashed, TokenType.INVITATION))
            .orElseThrow(() -> new IllegalArgumentException("Liên kết đặt lại mật khẩu không hợp lệ"));

        if (token.isUsed()) {
            throw new IllegalArgumentException("Liên kết đặt lại mật khẩu này đã được sử dụng");
        }
        if (token.isExpired()) {
            throw new IllegalArgumentException("Liên kết đặt lại mật khẩu đã hết hạn");
        }

        AppUser user = token.getUser();
        passwordPolicyValidator.validateNewPassword(newPassword, user.getUsername(), user.getEmail(), user.getId(), passwordEncoder);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        if (user.getStatus() == UserStatus.INVITED) {
            user.setStatus(UserStatus.ACTIVE);
        }
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        // Record in password history
        passwordHistoryRepository.save(new PasswordHistoryEntity(user, user.getPasswordHash()));

        // Invalidate all existing sessions
        sessionManagementService.revokeAllUserSessions(user.getUsername());

        auditService.logEvent(user.getEmail(), "PASSWORD_RESET_COMPLETED", "SUCCESS", "Đặt lại mật khẩu thành công và hủy mọi phiên cũ", request);
    }

    @Transactional
    public void changePassword(Long userId, String currentPassword, String newPassword, String currentSessionId, HttpServletRequest request) {
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Mật khẩu hiện tại không chính xác");
        }

        passwordPolicyValidator.validateNewPassword(newPassword, user.getUsername(), user.getEmail(), user.getId(), passwordEncoder);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordHistoryRepository.save(new PasswordHistoryEntity(user, user.getPasswordHash()));

        // Invalidate all other sessions, keep current session alive
        sessionManagementService.revokeAllOtherUserSessions(user.getUsername(), currentSessionId);

        auditService.logEvent(user.getEmail(), "PASSWORD_CHANGED", "SUCCESS", "Đổi mật khẩu thành công và hủy các phiên khác", request);
    }

    public void autoLogin(AppUser user, HttpServletRequest request, HttpServletResponse response) {
        SecurityUser userDetails = new SecurityUser(user);
        var auth = UsernamePasswordAuthenticationToken.authenticated(
            userDetails, null, userDetails.getAuthorities()
        );

        if (request.getSession(false) != null) {
            request.changeSessionId();
        }

        SecurityContext context = holder.createEmptyContext();
        context.setAuthentication(auth);
        holder.setContext(context);
        contextRepository.saveContext(context, request, response);

        request.getSession().setAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_2FA_VERIFIED, true);
    }
}
