package com.rf.labrex.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


// kendi validasyon anatasyonumuzu oluşturduk çalışma şartınıda UniqueNumberValid sınıfına bıraktık
@Constraint(
        validatedBy = UniqueNumberValid.class
)
@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueNumber {
    String message() default "Bu Tc kimlik numarası sisteme kayıtlı";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
