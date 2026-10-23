package com.fptaptech.auth.web;

import com.fptaptech.auth.security.RateLimiterService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
public class AuthController {

    private final UserService userService;
    private final RateLimiterService rateLimiterService;

    public AuthController(UserService userService, RateLimiterService rateLimiterService) {
        this.userService = userService;
        this.rateLimiterService = rateLimiterService;
    }

    @GetMapping("/login")
    public String login(Authentication authentication, Model model,
                        @RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "locked", required = false) String locked,
                        @RequestParam(value = "logout", required = false) String logout,
                        @RequestParam(value = "expired", required = false) String expired,
                        @RequestParam(value = "resetSuccess", required = false) String resetSuccess) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/";
        }
        if (error != null) {
            model.addAttribute("errorMessage", "Tên đăng nhập hoặc mật khẩu không chính xác.");
        }
        if (locked != null) {
            model.addAttribute("errorMessage", "Tài khoản của bạn đã bị khóa tạm thời 15 phút do nhập sai mật khẩu 5 lần liên tiếp.");
        }
        if (logout != null) {
            model.addAttribute("successMessage", "Bạn đã đăng xuất thành công khỏi hệ thống.");
        }
        if (expired != null) {
            model.addAttribute("errorMessage", "Phiên đăng nhập của bạn đã hết hạn hoặc bạn đã đăng nhập từ một thiết bị khác.");
        }
        if (resetSuccess != null) {
            model.addAttribute("successMessage", "Đặt lại mật khẩu thành công! Vui lòng đăng nhập bằng mật khẩu mới.");
        }
        return "login";
    }

    @GetMapping("/registration")
    public String registration(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/";
        }
        model.addAttribute("form", new RegistrationForm());
        return "registration";
    }

    @PostMapping("/registration")
    public String register(@Valid @ModelAttribute("form") RegistrationForm form,
                           BindingResult result,
                           HttpServletRequest request,
                           Model model) {
        String clientIp = rateLimiterService.extractClientIp(request);
        if (!rateLimiterService.allowRegistration(clientIp)) {
            result.reject("rateLimit", "Bạn đã thực hiện quá số lần đăng ký cho phép trong giờ này (tối đa 10 lần/giờ).");
            form.clearPasswords();
            return "registration";
        }

        if (result.hasErrors()) {
            form.clearPasswords();
            return "registration";
        }

        try {
            userService.register(form.getUsername(), form.getEmail(), form.getPassword(), request);
        } catch (IllegalArgumentException e) {
            String msg = e.getMessage();
            if (msg.contains("Username")) {
                result.rejectValue("username", "duplicate", msg);
            } else if (msg.contains("Email")) {
                result.rejectValue("email", "duplicate", msg);
            } else {
                result.rejectValue("password", "policy", msg);
            }
            form.clearPasswords();
            return "registration";
        }

        model.addAttribute("email", form.getEmail());
        return "registration-success";
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam("token") String token,
                              HttpServletRequest request,
                              HttpServletResponse response,
                              Model model) {
        try {
            userService.verifyEmail(token, request, response);
            return "redirect:/?verified=true";
        } catch (Exception e) {
            model.addAttribute("errorMessage", e.getMessage());
            return "verify-email-error";
        }
    }

    @GetMapping("/resend-verification")
    public String resendVerificationForm() {
        return "resend-verification";
    }

    @PostMapping("/resend-verification")
    public String resendVerification(@RequestParam("email") String email,
                                     HttpServletRequest request,
                                     Model model) {
        try {
            userService.resendVerificationEmail(email, request);
            model.addAttribute("successMessage", "Liên kết xác thực mới đã được gửi tới email của bạn (nếu tồn tại).");
        } catch (IllegalStateException e) {
            model.addAttribute("errorMessage", e.getMessage());
        }
        return "resend-verification";
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestParam("email") String email,
                                 HttpServletRequest request,
                                 Model model) {
        String clientIp = rateLimiterService.extractClientIp(request);
        if (!rateLimiterService.allowForgotPassword(clientIp)) {
            model.addAttribute("errorMessage", "Bạn đã gửi yêu cầu quá giới hạn cho phép (tối đa 20 lần/giờ). Vui lòng thử lại sau.");
            return "forgot-password";
        }

        userService.forgotPassword(email, request);
        // Blind response
        model.addAttribute("successMessage", "Nếu email của bạn tồn tại trong hệ thống, chúng tôi đã gửi liên kết đặt lại mật khẩu đến email đó. Vui lòng kiểm tra hộp thư (hiệu lực 30 phút).");
        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String resetPasswordForm(@RequestParam(value = "token", required = false) String token, Model model) {
        if (token == null || token.isBlank()) {
            model.addAttribute("errorMessage", "Liên kết không hợp lệ hoặc thiếu mã token.");
            return "verify-email-error";
        }
        ResetPasswordForm form = new ResetPasswordForm();
        form.setToken(token);
        model.addAttribute("form", form);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@Valid @ModelAttribute("form") ResetPasswordForm form,
                                BindingResult result,
                                HttpServletRequest request,
                                Model model) {
        if (result.hasErrors()) {
            form.clearPasswords();
            return "reset-password";
        }

        try {
            userService.resetPassword(form.getToken(), form.getPassword(), request);
            return "redirect:/login?resetSuccess=true";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            form.clearPasswords();
            return "reset-password";
        }
    }
}
