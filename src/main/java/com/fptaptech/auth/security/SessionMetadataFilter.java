package com.fptaptech.auth.security;

import com.fptaptech.auth.service.SessionManagementService;
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
public class SessionMetadataFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;
    private final SessionManagementService sessionManagementService;

    public SessionMetadataFilter(RateLimiterService rateLimiterService, SessionManagementService sessionManagementService) {
        this.rateLimiterService = rateLimiterService;
        this.sessionManagementService = sessionManagementService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (session != null && auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            if (session.getAttribute(SessionManagementService.ATTR_CLIENT_IP) == null) {
                String ip = rateLimiterService.extractClientIp(request);
                String userAgent = request.getHeader("User-Agent");
                session.setAttribute(SessionManagementService.ATTR_CLIENT_IP, ip);
                session.setAttribute(SessionManagementService.ATTR_USER_AGENT, userAgent != null ? userAgent : "Trình duyệt chuẩn");

                // Enforce max 2 concurrent sessions limit
                sessionManagementService.enforceConcurrentSessionLimit(auth.getName(), session.getId());
            }
        }

        filterChain.doFilter(request, response);
    }
}
