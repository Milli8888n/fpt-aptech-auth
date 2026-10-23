package com.fptaptech.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TwoFactorEnforcementFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Boolean verified = (Boolean) session.getAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_2FA_VERIFIED);
                if (Boolean.FALSE.equals(verified)) {
                    String uri = request.getRequestURI();

                    // Allow 2FA endpoints, logout, static resources, and error
                    boolean isAllowed = uri.startsWith("/2fa") ||
                                       uri.equals("/logout") ||
                                       uri.startsWith("/css") ||
                                       uri.startsWith("/js") ||
                                       uri.startsWith("/images") ||
                                       uri.equals("/error");

                    if (!isAllowed) {
                        Boolean forceSetup = (Boolean) session.getAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_FORCE_2FA_SETUP);
                        if (Boolean.TRUE.equals(forceSetup)) {
                            response.sendRedirect("/2fa/setup");
                        } else {
                            response.sendRedirect("/2fa/verify");
                        }
                        return;
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
