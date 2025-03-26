package com.rf.labrex.dto;

import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
@Data
@Builder
public class UpdateReportRequest {
    @Size(min = 5)
    private String title;
    @Size(min = 20)
    private String details;
    private LocalDateTime dateTime=LocalDateTime.now();
}
