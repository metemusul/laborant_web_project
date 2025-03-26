package com.rf.labrex.dto;


import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;
// login isteği yapılınca bu sınıf kullanılacak
@Data
@Builder
public class AuthRequest {
    @Size(min = 11,max = 11,message = "Tc kimlik numarası 11 haneli olmak zorunda")
    private String identificationNumber;
    private String password;
}
