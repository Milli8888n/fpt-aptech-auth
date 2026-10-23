package com.fptaptech.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@PasswordsMatch
public class ChangePasswordForm {

    @NotBlank(message = "{registration.required}")
    private String currentPassword;

    @NotBlank(message = "{registration.required}")
    @Size(min = 12, max = 64, message = "{registration.password.size}")
    private String newPassword;

    @NotBlank(message = "{registration.required}")
    private String newPasswordConfirm;

    public void clearPasswords() {
        this.currentPassword = "";
        this.newPassword = "";
        this.newPasswordConfirm = "";
    }

    public String getCurrentPassword() { return currentPassword; }
    public void setCurrentPassword(String currentPassword) { this.currentPassword = currentPassword; }

    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }

    public String getNewPasswordConfirm() { return newPasswordConfirm; }
    public void setNewPasswordConfirm(String newPasswordConfirm) { this.newPasswordConfirm = newPasswordConfirm; }
}
