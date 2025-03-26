package com.rf.labrex.dto;

import com.rf.labrex.entity.UserRole;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class WorkerDto {
    private String id;

    private String identificationNumber;
    @Enumerated(EnumType.STRING)
    private UserRole role;
    private String name;
    private String lastName;

    private HospitalDto hospital;
}
