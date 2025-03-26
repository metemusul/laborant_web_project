package com.rf.labrex.dto.converter;

import com.rf.labrex.dto.*;
import com.rf.labrex.entity.*;
import org.springframework.stereotype.Component;


// Bu sınıf modelleri dto sınıflarına çevirir
@Component
public class DtoConverter {
    public HospitalDto convertHospital(Hospital hospital){HospitalDto hospitalDto=HospitalDto.builder().id(hospital.getId()).image(hospital.getImage()).name(hospital.getName()).build();
    return hospitalDto;
    }
    public WorkerDto convertWorker(LaboratoryWorker worker){
        WorkerDto workerDto= WorkerDto.builder().id(worker.getId()).name(worker.getName()).lastName(worker.getLastName()).
        identificationNumber(worker.getIdentificationNumber()).role(worker.getRole()).hospital(convertHospital(worker.getHospital()))
                .build();
        return workerDto;
    }
    public PatientDto convertPatient(Patient patient){
        PatientDto dto=PatientDto.builder().
                name(patient.getName()).lastName(patient.getLastName()).id(patient.getId()).identificationNumber(patient.getIdentificationNumber())
                        .role(patient.getRole()).
                build();
        return dto;
    }
    public ReportDto convertReport(Report report){
        ReportDto reportDto=ReportDto.builder()
                .title(report.getTitle())
                .details(report.getDetails())
                .dateTime(report.getDateTime())
                .patient(convertPatient(report.getPatient()))
                .worker(convertWorker(report.getWorker()))
                .id(report.getId())
                .image(report.getImage())
                .build();
        return reportDto;
    }
    public BaseUserDto convertUser(BaseUser user){
        BaseUserDto baseUserDto= BaseUserDto.builder()
                .id(user.getId())
                .identificationNumber(user.getIdentificationNumber())
                .role(user.getRole())
                .build();
        return baseUserDto;
    }
}
