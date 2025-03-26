package com.rf.labrex.exception;

public class AuthException extends RuntimeException {
    public AuthException() {
        super("Şifre yanlış lütfen tekrar dene");
    }
}
