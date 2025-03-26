package com.rf.labrex.service;

import com.rf.labrex.dto.AuthDto;
import com.rf.labrex.dto.AuthRequest;
import com.rf.labrex.dto.BaseUserDto;
import com.rf.labrex.dto.converter.DtoConverter;
import com.rf.labrex.entity.BaseUser;
import com.rf.labrex.entity.Token;
import com.rf.labrex.exception.AuthException;
import com.rf.labrex.exception.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

// Strategy Design Pattern ile Auth işlemleri
interface authStrategy {
    AuthDto login(AuthRequest request);
    void logout(String cookie);
    BaseUserDto verifyToken(String cookie);
}

// DefaultAuthStrategy sınıfı
@Component
@RequiredArgsConstructor
class DefaultAuthStrategy implements authStrategy {

    private final TokenService tokenService;
    private final AppUserService appUserService;
    private final PasswordEncoder encoder;
    private final DtoConverter converter;

    @Override
    public AuthDto login(AuthRequest request) {
        BaseUser user = appUserService.findByIdentificationNumber(request.getIdentificationNumber());
        if (!encoder.matches(request.getPassword(), user.getPassword())) throw new AuthException();
        Token token = tokenService.createToken(user);
        return AuthDto.builder().token(token.getToken()).user(converter.convertUser(user)).build();
    }

    @Override
    public void logout(String cookie) {
        tokenService.logout(cookie);
    }

    @Override
    public BaseUserDto verifyToken(String cookie) {
        BaseUser baseUser = tokenService.verifyToken(cookie);
        if (baseUser == null) {
            throw new InvalidTokenException();
        }
        return converter.convertUser(baseUser);
    }
}

// AuthService sınıfı
@Service
@RequiredArgsConstructor
public class AuthService {
    private final com.rf.labrex.service.authStrategy authStrategy;

    public AuthDto login(AuthRequest request) {
        return authStrategy.login(request);
    }

    public void logout(String cookie) {
        authStrategy.logout(cookie);
    }

    public BaseUserDto verifyToken(String cookie) {
        return authStrategy.verifyToken(cookie);
    }
}
