package com.fptaptech.auth.security;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@Service
public class TotpService {

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(32);
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final EncryptionService encryptionService;
    private final SecureRandom secureRandom = new SecureRandom();

    public TotpService(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    public String generateNewSecret() {
        return secretGenerator.generate();
    }

    public String encryptSecret(String rawSecret) {
        return encryptionService.encrypt(rawSecret);
    }

    public String decryptSecret(String encryptedSecret) {
        return encryptionService.decrypt(encryptedSecret);
    }

    public String generateQrCodeDataUri(String email, String rawSecret) {
        try {
            QrData data = new QrData.Builder()
                .label(email)
                .secret(rawSecret)
                .issuer("FPT Aptech Portal")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

            byte[] imageData = qrGenerator.generate(data);
            return Utils.getDataUriForImage(imageData, qrGenerator.getImageMimeType());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate QR code", e);
        }
    }

    public boolean verifyCode(String rawSecret, String code) {
        if (rawSecret == null || code == null) return false;
        return codeVerifier.isValidCode(rawSecret, code.trim());
    }

    public List<String> generateRecoveryCodes() {
        List<String> codes = new ArrayList<>(10);
        for (int i = 0; i < 10; i++) {
            int part1 = 1000 + secureRandom.nextInt(9000);
            int part2 = 1000 + secureRandom.nextInt(9000);
            codes.add(part1 + "-" + part2);
        }
        return codes;
    }
}
