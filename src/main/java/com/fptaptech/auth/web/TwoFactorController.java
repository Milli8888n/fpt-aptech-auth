package com.fptaptech.auth.web;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.domain.RecoveryCodeEntity;
import com.fptaptech.auth.repository.RecoveryCodeRepository;
import com.fptaptech.auth.repository.UserRepository;
import com.fptaptech.auth.security.CustomAuthenticationSuccessHandler;
import com.fptaptech.auth.security.TotpService;
import com.fptaptech.auth.service.AuditService;
import com.fptaptech.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.List;

@Controller
@RequestMapping("/2fa")
public class TwoFactorController {

    private static final String SESSION_TEMP_SECRET = "TEMP_TOTP_SECRET";
    private static final String SESSION_TEMP_RECOVERY_CODES = "TEMP_RECOVERY_CODES";

    private final UserRepository userRepository;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final TotpService totpService;
    private final AuditService auditService;

    public TwoFactorController(
            UserRepository userRepository,
            RecoveryCodeRepository recoveryCodeRepository,
            TotpService totpService,
            AuditService auditService) {
        this.userRepository = userRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.totpService = totpService;
        this.auditService = auditService;
    }

    @GetMapping("/setup")
    public String setupPage(Authentication auth, HttpSession session, Model model) {
        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        String rawSecret = (String) session.getAttribute(SESSION_TEMP_SECRET);
        List<String> recoveryCodes = (List<String>) session.getAttribute(SESSION_TEMP_RECOVERY_CODES);

        if (rawSecret == null) {
            rawSecret = totpService.generateNewSecret();
            recoveryCodes = totpService.generateRecoveryCodes();
            session.setAttribute(SESSION_TEMP_SECRET, rawSecret);
            session.setAttribute(SESSION_TEMP_RECOVERY_CODES, recoveryCodes);
        }

        String qrCodeUri = totpService.generateQrCodeDataUri(user.getEmail(), rawSecret);
        model.addAttribute("qrCodeUri", qrCodeUri);
        model.addAttribute("secretKey", rawSecret);
        model.addAttribute("recoveryCodes", recoveryCodes);
        model.addAttribute("user", user);

        return "2fa/setup";
    }

    @PostMapping("/setup")
    public String confirmSetup(
            @RequestParam("code") String code,
            Authentication auth,
            HttpSession session,
            HttpServletRequest request,
            Model model) {
        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        String rawSecret = (String) session.getAttribute(SESSION_TEMP_SECRET);
        List<String> recoveryCodes = (List<String>) session.getAttribute(SESSION_TEMP_RECOVERY_CODES);

        if (rawSecret == null || !totpService.verifyCode(rawSecret, code)) {
            model.addAttribute("errorMessage", "Mã xác thực 6 chữ số không chính xác hoặc đã hết hạn. Vui lòng thử lại.");
            if (rawSecret != null) {
                model.addAttribute("qrCodeUri", totpService.generateQrCodeDataUri(user.getEmail(), rawSecret));
                model.addAttribute("secretKey", rawSecret);
                model.addAttribute("recoveryCodes", recoveryCodes);
            }
            return "2fa/setup";
        }

        // Encrypt secret and persist
        user.setTotpSecret(totpService.encryptSecret(rawSecret));
        user.setTotpEnabled(true);
        userRepository.save(user);

        // Delete old recovery codes if any, save new ones
        recoveryCodeRepository.deleteByUserId(user.getId());
        if (recoveryCodes != null) {
            for (String recoveryCode : recoveryCodes) {
                recoveryCodeRepository.save(new RecoveryCodeEntity(user, UserService.hashToken(recoveryCode.trim())));
            }
        }

        session.removeAttribute(SESSION_TEMP_SECRET);
        session.removeAttribute(SESSION_TEMP_RECOVERY_CODES);
        session.removeAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_FORCE_2FA_SETUP);
        session.setAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_2FA_VERIFIED, true);

        auditService.logEvent(user.getEmail(), "2FA_ENABLED", "SUCCESS", "Kích hoạt xác thực 2 bước (TOTP RFC 6238) thành công", request);

        model.addAttribute("recoveryCodes", recoveryCodes);
        return "2fa/setup-success";
    }

    @GetMapping("/verify")
    public String verifyPage(Authentication auth, Model model) {
        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        model.addAttribute("email", user.getEmail());
        return "2fa/verify";
    }

    @PostMapping("/verify")
    public String verifyCode(
            @RequestParam("code") String codeInput,
            Authentication auth,
            HttpSession session,
            HttpServletRequest request,
            Model model) {
        AppUser user = userRepository.findByUsernameOrEmail(auth.getName())
            .orElseThrow(() -> new IllegalArgumentException("Người dùng không tồn tại"));

        String rawSecret = totpService.decryptSecret(user.getTotpSecret());
        String code = codeInput != null ? codeInput.trim() : "";

        // Check TOTP 6-digit code
        if (code.length() == 6 && totpService.verifyCode(rawSecret, code)) {
            session.setAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_2FA_VERIFIED, true);
            auditService.logEvent(user.getEmail(), "2FA_VERIFY_SUCCESS", "SUCCESS", "Xác thực 2 bước bằng mã OTP thành công", request);
            return "redirect:/";
        }

        // Check 10 single-use recovery codes
        String codeHash = UserService.hashToken(code);
        List<RecoveryCodeEntity> activeRecoveryCodes = recoveryCodeRepository.findByUserIdAndUsedFalse(user.getId());

        for (RecoveryCodeEntity rc : activeRecoveryCodes) {
            if (rc.getCodeHash().equalsIgnoreCase(codeHash)) {
                rc.setUsed(true);
                rc.setUsedAt(Instant.now());
                recoveryCodeRepository.save(rc);

                session.setAttribute(CustomAuthenticationSuccessHandler.SESSION_ATTR_2FA_VERIFIED, true);
                auditService.logEvent(user.getEmail(), "2FA_RECOVERY_CODE_USED", "SUCCESS", "Đăng nhập bằng mã khôi phục dự phòng 1 lần", request);
                return "redirect:/?recoveryUsed=true";
            }
        }

        auditService.logEvent(user.getEmail(), "2FA_VERIFY_FAILED", "FAILURE", "Mã xác thực 2 bước hoặc mã khôi phục không đúng", request);
        model.addAttribute("errorMessage", "Mã xác thực hoặc mã khôi phục không chính xác. Vui lòng thử lại.");
        model.addAttribute("email", user.getEmail());
        return "2fa/verify";
    }
}
