package com.rf.labrex.dto;

import com.rf.labrex.entity.Patient;
import com.rf.labrex.entity.UserRole;
import com.rf.labrex.validation.UniqueNumber;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SavePatientRequest {
    @Size(min = 11,max = 11,message = "Tc kimlik numarası 11 haneli olmak zorunda")
    @UniqueNumber
    private String identificationNumber;
    @NotNull
    @Size(min = 8,max = 256)
    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{5,}$" ,message = "Lütfen en az bir büyük harf,bir küçük harf ve sayi kullanin")
    private String password;

    @Size(min = 2)

    private String name;
    @Size(min = 2)
    private String lastName;

    public Patient toPatient(SavePatientRequest request){
        Patient patient=Patient.builder().name(request.getName()).lastName(request.lastName).build();
        patient.setRole(UserRole.ROLE_PATIENT);
        patient.setIdentificationNumber(request.identificationNumber);
        patient.setPassword(request.getPassword());
        return patient;
    }
}
