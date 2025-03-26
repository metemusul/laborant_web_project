package com.rf.labrex.dto;


import lombok.Builder;
import lombok.Data;

// giriş başarılı olduğu takdirde cevap olarak bu sınıf dönecek

@Data
@Builder
public class AuthDto {
    private  String token;
    private BaseUserDto user;
}
