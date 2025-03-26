package com.rf.labrex.controller;

import com.rf.labrex.dto.AuthDto;
import com.rf.labrex.dto.AuthRequest;
import com.rf.labrex.dto.BaseUserDto;
import com.rf.labrex.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("api/v1/auth")

public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // login
    @PostMapping("/login")
    public ResponseEntity<AuthDto> login(@Valid @RequestBody AuthRequest request){
        int oneMonth = 30 * 24 * 60 * 60;
        AuthDto dto=authService.login(request);
        ResponseCookie cookie=ResponseCookie.from("auth-token",dto.getToken()).path("/").maxAge(oneMonth).httpOnly(true).build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,cookie.toString()).body(dto);
    }
    // logout
    @DeleteMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "auth-token",required = false) String cookie){
        authService.logout(cookie);
        ResponseCookie cook=ResponseCookie.from("auth-token","").path("/").maxAge(0).httpOnly(true).build();

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE,cook.toString()).body("Başari ile Çıkış Yapıldı");
    }
    // verify
    @GetMapping("/verify")
    public ResponseEntity<BaseUserDto> verifyUser(@CookieValue(name = "auth-token",required = false) String cookie ){
        return ResponseEntity.ok(authService.verifyToken(cookie));
    }
}
