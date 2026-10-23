package com.fptaptech.auth.security;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

@Service
public class TimingDefenseService {

    // Pre-computed BCrypt hash with cost factor 10 to simulate realistic password check latency
    private static final String DUMMY_BCRYPT_HASH = "$2a$10$wT8K8B2aN0c.N0v4I7YjjeC3kQ6v2m7q8e8n8o8p8q8r8s8t8u8v8";

    /**
     * Executes a dummy BCrypt check to consume identical CPU cycles when a user is not found,
     * ensuring response time delta between non-existent user and wrong password remains <= 50ms (anti-timing attack).
     */
    public void performDummyPasswordCheck(String rawPassword) {
        String testInput = rawPassword != null ? rawPassword : "dummy_password_timing_shield";
        try {
            BCrypt.checkpw(testInput, DUMMY_BCRYPT_HASH);
        } catch (Exception ignored) {
        }
    }
}
