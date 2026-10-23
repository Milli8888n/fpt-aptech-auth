package com.fptaptech.auth.web;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ProfileController {

    private final UserRepository userRepository;
    private final UserService userService;

    public ProfileController(UserRepository userRepository, UserService userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @GetMapping("/")
    public String welcome(Authentication auth, Model model,
                          @RequestParam(value = "verified", required = false) String verified,
                          @RequestParam(value = "recoveryUsed", required = false) String recoveryUsed) {
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            AppUser user = userRepository.findByUsernameOrEmail(auth.getName()).orElse(null);
            model.addAttribute("currentUser", user);
        }
        if (verified != null) {
            model.addAttribute("successMessage", "Chúc mừng! Email của bạn đã được xác thực thành công. Tài khoản đã sẵn sàng sử dụng.");
        }
        if (recoveryUsed != null) {
            model.addAttribute("warningMessage", "Bạn vừa đăng nhập bằng 1 mã khôi phục dự phòng. Mã này đã bị hủy, vui lòng kiểm tra lại thiết bị 2FA.");
        }
        return "welcome";
    }

    @GetMapping("/profile")
    public String profile(Authentication auth, Model model,
                          @RequestParam(value = "passwordChanged", required = false) String passwordChanged) {
        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        model.addAttribute("user", user);
        if (passwordChanged != null) {
            model.addAttribute("successMessage", "Đổi mật khẩu thành công! Tất cả các phiên đăng nhập khác của bạn đã được đăng xuất.");
        }
        return "profile";
    }

    @GetMapping("/change-password")
    public String changePasswordForm(Model model) {
        model.addAttribute("form", new ChangePasswordForm());
        return "change-password";
    }

    @PostMapping("/change-password")
    public String changePassword(@Valid @ModelAttribute("form") ChangePasswordForm form,
                                 BindingResult result,
                                 Authentication auth,
                                 HttpSession session,
                                 HttpServletRequest request,
                                 Model model) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "change-password";
        }

        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        try {
            userService.changePassword(user.getId(), form.getCurrentPassword(), form.getNewPassword(), session.getId(), request);
            return "redirect:/profile?passwordChanged=true";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            form.clearPasswords();
            return "change-password";
        }
    }
}
