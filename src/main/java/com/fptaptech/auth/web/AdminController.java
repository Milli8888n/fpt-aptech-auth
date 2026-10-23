package com.fptaptech.auth.web;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.AuditLogEntity;
import com.fptaptech.auth.domain.Role;
import com.fptaptech.auth.domain.UserStatus;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.AdminService;
import com.fptaptech.auth.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final AdminService adminService;
    private final AuditService auditService;
    private final UserRepository userRepository;

    public AdminController(AdminService adminService, AuditService auditService, UserRepository userRepository) {
        this.adminService = adminService;
        this.auditService = auditService;
        this.userRepository = userRepository;
    }

    private AppUser getCurrentAdmin(Authentication auth) {
        return userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalStateException("Quản trị viên không tồn tại"));
    }

    @GetMapping("/users")
    public String listUsers(
            @RequestParam(value = "query", required = false) String query,
            @RequestParam(value = "role", required = false) String role,
            @RequestParam(value = "status", required = false) String statusStr,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size,
            Model model) {

        UserStatus status = null;
        if (statusStr != null && !statusStr.isBlank()) {
            try {
                status = UserStatus.valueOf(statusStr);
            } catch (IllegalArgumentException ignored) {}
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        Page<AppUser> usersPage = adminService.searchUsers(query, role, status, pageable);

        model.addAttribute("usersPage", usersPage);
        model.addAttribute("query", query);
        model.addAttribute("role", role);
        model.addAttribute("status", statusStr);
        model.addAttribute("currentPage", page);

        return "admin/users";
    }

    @PostMapping("/users/{id}/lock")
    public String lockUser(@PathVariable("id") Long id, HttpServletRequest request, RedirectAttributes ra) {
        try {
            adminService.lockUser(id, request);
            ra.addFlashAttribute("successMessage", "Khóa tài khoản thành công.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/unlock")
    public String unlockUser(@PathVariable("id") Long id, HttpServletRequest request, RedirectAttributes ra) {
        try {
            adminService.unlockUser(id, request);
            ra.addFlashAttribute("successMessage", "Mở khóa tài khoản thành công.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/toggle-disable")
    public String toggleDisableUser(@PathVariable("id") Long id, Authentication auth, HttpServletRequest request, RedirectAttributes ra) {
        try {
            AppUser currentAdmin = getCurrentAdmin(auth);
            adminService.toggleDisableUser(id, currentAdmin.getId(), request);
            ra.addFlashAttribute("successMessage", "Cập nhật trạng thái kích hoạt/vô hiệu hóa tài khoản thành công.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/change-role")
    public String changeRole(
            @PathVariable("id") Long id,
            @RequestParam("role") String role,
            Authentication auth,
            HttpServletRequest request,
            RedirectAttributes ra) {
        try {
            AppUser currentAdmin = getCurrentAdmin(auth);
            adminService.changeRole(id, role, currentAdmin.getId(), request);
            ra.addFlashAttribute("successMessage", "Đổi vai trò người dùng thành công.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/force-logout")
    public String forceLogout(@PathVariable("id") Long id, HttpServletRequest request, RedirectAttributes ra) {
        try {
            adminService.forceLogout(id, request);
            ra.addFlashAttribute("successMessage", "Đã buộc đăng xuất toàn bộ phiên của người dùng.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @GetMapping("/invite")
    public String inviteForm() {
        return "admin/invite";
    }

    @PostMapping("/invite")
    public String inviteUser(
            @RequestParam("email") String email,
            @RequestParam("username") String username,
            @RequestParam("role") String role,
            HttpServletRequest request,
            RedirectAttributes ra,
            Model model) {
        try {
            adminService.inviteUser(email, username, role, request);
            ra.addFlashAttribute("successMessage", "Đã gửi email mời kích hoạt tài khoản thành công tới: " + email);
            return "redirect:/admin/users";
        } catch (Exception e) {
            model.addAttribute("errorMessage", e.getMessage());
            model.addAttribute("email", email);
            model.addAttribute("username", username);
            model.addAttribute("role", role);
            return "admin/invite";
        }
    }

    @GetMapping("/audit-logs")
    public String auditLogs(
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "action", required = false) String action,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "15") int size,
            Model model) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("eventTime").descending());
        Page<AuditLogEntity> auditPage = auditService.getAuditLogs(email, action, status, pageable);

        model.addAttribute("auditPage", auditPage);
        model.addAttribute("email", email);
        model.addAttribute("action", action);
        model.addAttribute("status", status);
        model.addAttribute("currentPage", page);

        return "admin/audit-logs";
    }
}
