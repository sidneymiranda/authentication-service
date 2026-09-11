package com.github.sidneymiranda.authservice.controller.validator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordStrengthValidator.class)
public @interface ValidPassword {
    String message() default "Password does not meet the minimum security requirements";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
