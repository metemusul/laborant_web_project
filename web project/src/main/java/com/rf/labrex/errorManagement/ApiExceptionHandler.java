package com.rf.labrex.errorManagement;

import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.exception.AuthException;
import com.rf.labrex.exception.AuthorizationException;
import com.rf.labrex.exception.InvalidTokenException;
import com.rf.labrex.exception.NotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
// bu sınıf hataların yönetiminin yapıldığı yer amaç isteklere analaşılır cevaplar dönmek
@RestControllerAdvice
public class ApiExceptionHandler {

    // validayon hataları
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> validationErrorHandler(MethodArgumentNotValidException ex, HttpServletRequest request) {
        ApiResponse apiError = new ApiResponse();
        Map<String, String> errors = new HashMap<>();
        for (FieldError fieldError : ex.getFieldErrors()) {
            errors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }
        apiError = ApiResponse.builder().dateTime(apiError.getDateTime()).errors(errors).message("validation Error").status(400).path(request.getRequestURI()).build();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiError);
    }
    // not found hataları
    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiResponse> NotFoundException(RuntimeException ex,HttpServletRequest request){
        ApiResponse apiResponse=new ApiResponse();
        apiResponse=ApiResponse.builder().path(request.getRequestURI()).message(ex.getMessage()).status(404).dateTime(apiResponse.getDateTime()).build();
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiResponse);
    }
    // bad request hataları
    @ExceptionHandler({AuthException.class, InvalidTokenException.class})
   public ResponseEntity<ApiResponse> BadRequestException(RuntimeException ex,HttpServletRequest request){
        ApiResponse apiResponse=ApiResponse.builder()
                .path(request.getRequestURI())
                .dateTime(LocalDateTime.now())
                .message(ex.getMessage())
                .status(400)
                .build();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);
    }
    // yetki hataları
    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<ApiResponse> UnauthorizedException(RuntimeException ex,HttpServletRequest request){
        ApiResponse apiResponse=ApiResponse.builder()
                .path(request.getRequestURI())
                .dateTime(LocalDateTime.now())
                .message(ex.getMessage())
                .status(401)
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(apiResponse);
    }

}
