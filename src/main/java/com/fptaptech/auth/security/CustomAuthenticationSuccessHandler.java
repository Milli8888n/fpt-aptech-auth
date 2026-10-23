package com.fptaptech.auth.security;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.Role;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String SESSION_ATTR_2FA_VERIFIED = "2FA_VERIFIED";
    public static final String SESSION_ATTR_FORCE_2FA_SETUP = "FORCE_2FA_SETUP";

    private final UserRepository userRepository;
    private final AuditService auditService;

    public CustomAuthenticationSuccessHandler(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
        setDefaultTargetUrl("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String username = authentication.getName();
        AppUser user = userRepository.findByUsernameOrEmail(username).orElse(null);

        if (user != null) {
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);

            auditService.logEvent(user.getEmail(), "LOGIN_SUCCESS", "SUCCESS", "Đăng nhập mật khẩu thành công", request);

            HttpSession session = request.getSession();

            // Check 2FA requirements
            if (user.isTotpEnabled()) {
                session.setAttribute(SESSION_ATTR_2FA_VERIFIED, false);
                getRedirectStrategy().sendRedirect(request, response, "/2fa/verify");
                return;
            } else if (user.hasRole(Role.LECTURER) || user.hasRole(Role.ADMIN)) {
                // Mandatory 2FA for Lecturer and Admin
                session.setAttribute(SESSION_ATTR_2FA_VERIFIED, false);
                session.setAttribute(SESSION_ATTR_FORCE_2FA_SETUP, true);
                getRedirectStrategy().sendRedirect(request, response, "/2fa/setup");
                return;
            } else {
                session.setAttribute(SESSION_ATTR_2FA_VERIFIED, true);
            }
        }

        getRedirectStrategy().sendRedirect(request, response, "/");
    }
}
