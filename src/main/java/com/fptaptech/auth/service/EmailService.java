package com.fptaptech.auth.service;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final String baseUrl;
    private final String fromEmail;

    public EmailService(
            JavaMailSender mailSender,
            @Value("${app.base-url}") String baseUrl,
            @Value("${spring.mail.username:}") String mailUsername) {
        this.mailSender = mailSender;
        this.baseUrl = baseUrl;
        this.fromEmail = (mailUsername != null && !mailUsername.isBlank()) ? mailUsername : "portal@fpt.edu.vn";
    }

    public void sendVerificationEmail(String toEmail, String token) {
        String link = baseUrl + "/verify-email?token=" + token;
        log.info(">>> [ACTIONABLE LINK - EMAIL VERIFICATION] To: {} | Link: {}", toEmail, link);

        String subject = "[FPT Aptech Portal] Xác thực tài khoản của bạn";
        String htmlContent = "<div style='font-family: Arial, sans-serif; padding: 20px; color: #333;'>"
            + "<h2>Chào mừng bạn đến với Cổng tài khoản FPT Aptech!</h2>"
            + "<p>Vui lòng nhấp vào liên kết bên dưới để xác thực địa chỉ email và kích hoạt tài khoản của bạn:</p>"
            + "<p style='margin: 25px 0;'><a href='" + link + "' style='background-color: #0d6efd; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>Xác thực tài khoản</a></p>"
            + "<p>Hoặc dán liên kết này vào trình duyệt: <a href='" + link + "'>" + link + "</a></p>"
            + "<p><i>Liên kết này có hiệu lực trong vòng 24 giờ.</i></p>"
            + "</div>";

        sendHtmlEmail(toEmail, subject, htmlContent);
    }

    public void sendPasswordResetEmail(String toEmail, String token) {
        String link = baseUrl + "/reset-password?token=" + token;
        log.info(">>> [ACTIONABLE LINK - PASSWORD RESET] To: {} | Link: {}", toEmail, link);

        String subject = "[FPT Aptech Portal] Yêu cầu đặt lại mật khẩu";
        String htmlContent = "<div style='font-family: Arial, sans-serif; padding: 20px; color: #333;'>"
            + "<h2>Yêu cầu đặt lại mật khẩu</h2>"
            + "<p>Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản liên kết với email này.</p>"
            + "<p style='margin: 25px 0;'><a href='" + link + "' style='background-color: #dc3545; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>Đặt lại mật khẩu</a></p>"
            + "<p>Hoặc dán liên kết này vào trình duyệt: <a href='" + link + "'>" + link + "</a></p>"
            + "<p><i>Liên kết này có hiệu lực trong vòng 30 phút. Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.</i></p>"
            + "</div>";

        sendHtmlEmail(toEmail, subject, htmlContent);
    }

    public void sendInvitationEmail(String toEmail, String roleName, String token) {
        String link = baseUrl + "/reset-password?token=" + token;
        log.info(">>> [ACTIONABLE LINK - INVITATION] To: {} | Role: {} | Link: {}", toEmail, roleName, link);

        String roleDisplay = "ROLE_ADMIN".equals(roleName) ? "Quản trị viên" : "Giảng viên";
        String subject = "[FPT Aptech Portal] Lời mời tham gia hệ thống với vai trò " + roleDisplay;
        String htmlContent = "<div style='font-family: Arial, sans-serif; padding: 20px; color: #333;'>"
            + "<h2>Chào mừng bạn đến với FPT Aptech Portal!</h2>"
            + "<p>Bạn đã được Quản trị viên mời tham gia hệ thống với vai trò <strong>" + roleDisplay + "</strong>.</p>"
            + "<p>Vui lòng nhấp vào liên kết bên dưới để thiết lập mật khẩu ban đầu và kích hoạt tài khoản của bạn:</p>"
            + "<p style='margin: 25px 0;'><a href='" + link + "' style='background-color: #198754; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>Thiết lập mật khẩu</a></p>"
            + "<p>Hoặc dán liên kết này vào trình duyệt: <a href='" + link + "'>" + link + "</a></p>"
            + "<p><i>Liên kết này có hiệu lực trong vòng 24 giờ.</i></p>"
            + "</div>";

        sendHtmlEmail(toEmail, subject, htmlContent);
    }

    private void sendHtmlEmail(String toEmail, String subject, String htmlContent) {
        log.info(">>> [FPT-PORTAL-EMAIL] Sending '{}' to '{}' from '{}'...", subject, toEmail, fromEmail);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromEmail, "FPT Aptech Portal");
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);
            mailSender.send(message);
            log.info(">>> [FPT-PORTAL-EMAIL SUCCESS] Delivered email successfully to {}", toEmail);
        } catch (Exception e) {
            log.warn(">>> [FPT-PORTAL-EMAIL WARNING] SMTP delivery failed to {}: {}", toEmail, e.getMessage());
        }
    }
}
