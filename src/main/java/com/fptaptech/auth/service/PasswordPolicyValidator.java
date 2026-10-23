package com.fptaptech.auth.service;

import com.fptaptech.auth.domain.PasswordHistoryEntity;
import com.fptaptech.auth.repository.PasswordHistoryRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class PasswordPolicyValidator {

    private final PasswordHistoryRepository passwordHistoryRepository;
    private final Set<String> commonPasswords = new HashSet<>();

    public PasswordPolicyValidator(PasswordHistoryRepository passwordHistoryRepository) {
        this.passwordHistoryRepository = passwordHistoryRepository;
    }

    @PostConstruct
    void loadCommonPasswords() {
        try {
            ClassPathResource resource = new ClassPathResource("common-passwords-10k.txt");
            if (resource.exists()) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String trimmed = line.trim().toLowerCase(Locale.ROOT);
                        if (!trimmed.isEmpty()) {
                            commonPasswords.add(trimmed);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Log and fallback
        }
    }

    public void validateNewPassword(String rawPassword, String username, String email, Long userId, PasswordEncoder encoder) {
        if (rawPassword == null || rawPassword.length() < 12) {
            throw new IllegalArgumentException("Mật khẩu phải dài tối thiểu 12 ký tự");
        }

        String lowerPass = rawPassword.toLowerCase(Locale.ROOT);

        // Check if contains username
        if (username != null && !username.isBlank()) {
            String lowerUsername = username.toLowerCase(Locale.ROOT);
            if (lowerPass.contains(lowerUsername)) {
                throw new IllegalArgumentException("Mật khẩu không được chứa tên đăng nhập");
            }
        }

        // Check if contains email local part
        if (email != null && !email.isBlank()) {
            String localPart = email.split("@")[0].toLowerCase(Locale.ROOT);
            if (localPart.length() >= 3 && lowerPass.contains(localPart)) {
                throw new IllegalArgumentException("Mật khẩu không được chứa địa chỉ email");
            }
        }

        // Check common passwords list
        if (commonPasswords.contains(lowerPass)) {
            throw new IllegalArgumentException("Mật khẩu này quá phổ biến và dễ đoán, vui lòng chọn mật khẩu khác");
        }

        // Check last 5 passwords history if userId is provided
        if (userId != null && encoder != null) {
            List<PasswordHistoryEntity> history = passwordHistoryRepository.findTop5ByUserIdOrderByCreatedAtDesc(userId);
            for (PasswordHistoryEntity item : history) {
                if (encoder.matches(rawPassword, item.getPasswordHash())) {
                    throw new IllegalArgumentException("Mật khẩu mới không được trùng với 5 mật khẩu gần nhất của bạn");
                }
            }
        }
    }
}
