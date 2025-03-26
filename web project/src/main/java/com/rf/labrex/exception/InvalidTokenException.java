package com.rf.labrex.exception;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException() {
        super("Token Artik Geçersiz Çıkış Yap");
    }
}
