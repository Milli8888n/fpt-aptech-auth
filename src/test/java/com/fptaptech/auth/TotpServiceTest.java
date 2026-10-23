package com.fptaptech.auth;

import com.fptaptech.auth.security.EncryptionService;
import com.fptaptech.auth.security.TotpService;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TotpServiceTest {

    private TotpService totpService;
    private EncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        encryptionService = new EncryptionService("FptAptechAuthSecret2026AESGCM256Key!!");
        totpService = new TotpService(encryptionService);
    }

    @Test
    @DisplayName("F6: Sinh khóa bí mật TOTP và mã hóa an toàn bằng AES-GCM")
    void testSecretGenerationAndEncryption() {
        String secret = totpService.generateNewSecret();
        assertNotNull(secret);
        assertTrue(secret.length() >= 16);

        String encrypted = totpService.encryptSecret(secret);
        assertNotEquals(secret, encrypted);

        String decrypted = totpService.decryptSecret(encrypted);
        assertEquals(secret, decrypted);
    }

    @Test
    @DisplayName("F6: Sinh mã QR Code Data URI hợp lệ (data:image/png;base64,...)")
    void testQrCodeGeneration() {
        String secret = totpService.generateNewSecret();
        String qrUri = totpService.generateQrCodeDataUri("test@fpt.edu.vn", secret);

        assertNotNull(qrUri);
        assertTrue(qrUri.startsWith("data:image/png;base64,"));
    }

    @Test
    @DisplayName("F6: Xác thực mã TOTP 6 số hợp lệ theo chuẩn RFC 6238")
    void testTotpCodeVerification() throws Exception {
        String secret = totpService.generateNewSecret();

        CodeGenerator generator = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
        long currentBucket = new SystemTimeProvider().getTime() / 30;
        String validCode = generator.generate(secret, currentBucket);

        assertTrue(totpService.verifyCode(secret, validCode));
        assertFalse(totpService.verifyCode(secret, "000000"));
    }

    @Test
    @DisplayName("F6: Sinh chính xác 10 mã khôi phục dùng 1 lần dạng XXXX-XXXX")
    void testRecoveryCodesGeneration() {
        List<String> recoveryCodes = totpService.generateRecoveryCodes();
        assertNotNull(recoveryCodes);
        assertEquals(10, recoveryCodes.size());

        for (String code : recoveryCodes) {
            assertTrue(code.matches("\\d{4}-\\d{4}"));
        }
    }
}
