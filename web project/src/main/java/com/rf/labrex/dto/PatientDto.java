package com.rf.labrex.dto;

import com.rf.labrex.entity.UserRole;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PatientDto {
    private String id;

    private String identificationNumber;
    @Enumerated(EnumType.STRING)
    private UserRole role;
    private String name;
    private String lastName;
}
