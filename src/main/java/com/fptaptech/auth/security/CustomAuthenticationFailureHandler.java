package com.fptaptech.auth.security;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserRepository userRepository;
    private final AuditService auditService;

    public CustomAuthenticationFailureHandler(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String login = request.getParameter("username");
        if (login != null) {
            login = DatabaseUserDetailsService.normalize(login);
            AppUser user = userRepository.findByUsernameOrEmail(login).orElse(null);

            if (user != null) {
                // If account is currently locked
                if (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null && Instant.now().isBefore(user.getLockedUntil())) {
                    auditService.logEvent(user.getEmail(), "LOGIN_BLOCKED", "FAILURE", "Đăng nhập bị chặn do tài khoản đang bị khóa tạm thời", request);
                    getRedirectStrategy().sendRedirect(request, response, "/login?locked=true");
                    return;
                }

                // Increment failed attempts
                int attempts = user.getFailedAttempts() + 1;
                user.setFailedAttempts(attempts);

                if (attempts >= 5) {
                    user.setStatus(UserStatus.LOCKED);
                    user.setLockedUntil(Instant.now().plusSeconds(900)); // Lock for 15 minutes
                    userRepository.save(user);
                    auditService.logEvent(user.getEmail(), "ACCOUNT_LOCKED", "FAILURE", "Sai mật khẩu 5 lần, khóa tài khoản 15 phút", request);
                    getRedirectStrategy().sendRedirect(request, response, "/login?locked=true");
                    return;
                } else {
                    userRepository.save(user);
                    auditService.logEvent(user.getEmail(), "LOGIN_FAILED", "FAILURE", "Sai mật khẩu (lần " + attempts + "/5)", request);
                }
            } else {
                auditService.logEvent(login, "LOGIN_FAILED", "FAILURE", "Đăng nhập thất bại (tài khoản không tồn tại)", request);
            }
        }

        getRedirectStrategy().sendRedirect(request, response, "/login?error=true");
    }
}
