package com.rf.labrex.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
@Data
@Builder
public class ReportDto {
    private String id;

    private PatientDto patient;

    private WorkerDto worker;
    private String title;
    private String details;
    private LocalDateTime dateTime=LocalDateTime.now();
    private String image;
}
