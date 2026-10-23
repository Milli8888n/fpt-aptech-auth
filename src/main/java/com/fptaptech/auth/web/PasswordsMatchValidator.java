package com.fptaptech.auth.web;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Objects;

public class PasswordsMatchValidator implements ConstraintValidator<PasswordsMatch, Object> {

    @Override
    public boolean isValid(Object form, ConstraintValidatorContext context) {
        if (form instanceof RegistrationForm rf) {
            if (rf.getPassword() == null || rf.getPasswordConfirm() == null) {
                return true;
            }
            if (Objects.equals(rf.getPassword(), rf.getPasswordConfirm())) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                .addPropertyNode("passwordConfirm")
                .addConstraintViolation();
            return false;
        } else if (form instanceof ResetPasswordForm rpf) {
            if (rpf.getPassword() == null || rpf.getPasswordConfirm() == null) {
                return true;
            }
            if (Objects.equals(rpf.getPassword(), rpf.getPasswordConfirm())) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                .addPropertyNode("passwordConfirm")
                .addConstraintViolation();
            return false;
        } else if (form instanceof ChangePasswordForm cpf) {
            if (cpf.getNewPassword() == null || cpf.getNewPasswordConfirm() == null) {
                return true;
            }
            if (Objects.equals(cpf.getNewPassword(), cpf.getNewPasswordConfirm())) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                .addPropertyNode("newPasswordConfirm")
                .addConstraintViolation();
            return false;
        }
        return true;
    }
}
