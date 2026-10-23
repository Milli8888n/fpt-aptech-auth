package com.fptaptech.auth.web;

import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.SessionManagementService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class SessionController {

    private final SessionManagementService sessionManagementService;
    private final AuditService auditService;

    public SessionController(SessionManagementService sessionManagementService, AuditService auditService) {
        this.sessionManagementService = sessionManagementService;
        this.auditService = auditService;
    }

    @GetMapping("/sessions")
    public String sessions(Authentication auth, HttpSession session, Model model,
                           @RequestParam(value = "revoked", required = false) String revoked) {
        List<SessionManagementService.ActiveSessionDto> activeSessions =
            sessionManagementService.getUserSessions(auth.getName(), session.getId());

        model.addAttribute("sessions", activeSessions);
        model.addAttribute("currentSessionId", session.getId());
        if (revoked != null) {
            model.addAttribute("successMessage", "Đã hủy phiên đăng nhập từ xa thành công.");
        }
        return "sessions";
    }

    @PostMapping("/sessions/revoke")
    public String revokeSession(@RequestParam("sessionId") String targetSessionId,
                                Authentication auth,
                                HttpSession session,
                                HttpServletRequest request) {
        sessionManagementService.revokeSession(targetSessionId);
        auditService.logEvent(auth.getName(), "SESSION_REVOKED", "SUCCESS", "Đăng xuất từ xa phiên ID: " + targetSessionId, request);

        if (targetSessionId.equals(session.getId())) {
            session.invalidate();
            return "redirect:/login?logout=true";
        }
        return "redirect:/sessions?revoked=true";
    }
}
