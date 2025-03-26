package com.rf.labrex.service;

import com.rf.labrex.config.QueryConfig;
import com.rf.labrex.dto.ReportDto;
import com.rf.labrex.dto.SaveReportRequest;
import com.rf.labrex.dto.UpdateReportRequest;
import com.rf.labrex.dto.converter.DtoConverter;
import com.rf.labrex.entity.LaboratoryWorker;
import com.rf.labrex.entity.Patient;
import com.rf.labrex.entity.Report;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.exception.AuthorizationException;
import com.rf.labrex.exception.NotFoundException;
import com.rf.labrex.repository.ReportRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;


// rapor işlemlerinin yapıldığı sınıf
@Service
@RequiredArgsConstructor
public class ReportService {
    private final ReportRepository reportRepository;
    private final WorkerService workerService;
    private final PatientService patientService;
    private final DtoConverter converter;
    private final QueryConfig config;

    public ApiResponse save(SaveReportRequest request, String workerId, String patientId, HttpServletRequest url) {
        ApiResponse apiResponse = new ApiResponse();
        LaboratoryWorker worker = workerService.findById(workerId);
        Patient patient = patientService.findById(patientId);
        Report report=Report.builder().title(request.getTitle()).details(request.getDetails()).worker(worker).patient(patient).dateTime(LocalDateTime.now()).build();
        reportRepository.save(report);
        apiResponse=ApiResponse.builder().status(200).path(url.getRequestURI()).message("Rapor Oluşturuldu").dateTime(apiResponse.getDateTime()).build();
        return apiResponse;
    }

    public ApiResponse update(UpdateReportRequest request, String id, HttpServletRequest path) {
        ApiResponse apiResponse=new ApiResponse();
        Report report=findById(id);
        if(!config.isAuthorized(report.getWorker(),config.getAuthentication())) throw new AuthorizationException();
        report.setDateTime(request.getDateTime());
        report.setTitle(request.getTitle());
        report.setDetails(request.getDetails());
        reportRepository.save(report);
        apiResponse=ApiResponse.builder().status(200).path(path.getRequestURI()).message("Rapor Güncellendi").dateTime(apiResponse.getDateTime()).build();
        return apiResponse;
    }
    public ApiResponse delete(String id,HttpServletRequest path) {
        Report report=findById(id);
        if(!config.isAuthorized(report.getWorker(),config.getAuthentication())) throw new AuthorizationException();
        reportRepository.delete(report);
        return ApiResponse.builder().status(200).path(path.getRequestURI()).message("Rapor Silindi").dateTime(LocalDateTime.now()).build();
    }
    protected Report findById(String id){
        return reportRepository.findById(id).orElseThrow(()->new NotFoundException("Rapor"));
    }

    public Page<ReportDto> reportsForWorker(String workerId, int page, int size) {
        Page<Report> list=reportRepository.findByWorkerId(workerId,PageRequest.of(page,size));
        return list.map(converter::convertReport);
    }

    public Page<ReportDto> reportsForPatient(String patientId, int page, int size) {
        Page<Report> list=reportRepository.findByPatientId(patientId,PageRequest.of(page,size));
        return list.map(converter::convertReport);
    }

    public Page<ReportDto> sortByDate(String workerID, int page, int size) {
        Page<Report> list=reportRepository.findByWorkerIdOrderByDateTimeDesc(workerID,PageRequest.of(page,size));
        return list.map(converter::convertReport);
    }

    public ReportDto getReport(String id) {
        Report report=findById(id);
        if(!(config.isAuthorized(report.getWorker(),config.getAuthentication()) || config.isAuthorized(report.getPatient(),config.getAuthentication()))) throw new AuthorizationException();
        return converter.convertReport(report);
    }

    public List<ReportDto> search(String value) {
        // hasta ad soyad tc numarası,laborant ad soyada tc numarasına başlık ve detaylara göre arama
        List<Report> reports=reportRepository.findByWorkerNameContainingIgnoreCaseOrWorkerLastNameContainingIgnoreCaseOrWorkerIdentificationNumberContainingIgnoreCaseOrPatientNameContainingIgnoreCaseOrPatientLastNameContainingIgnoreCaseOrPatientIdentificationNumberContainingIgnoreCaseOrTitleContainingIgnoreCaseOrDetailsContainingIgnoreCase(value,value,value,value,value,value,value,value);
        return reports.stream().map(converter::convertReport).collect(Collectors.toList());
    }

    public Page<ReportDto> sortingByDateForWorker(String patientId, int page, int size) {
        Page<Report> list=reportRepository.findByPatientIdOrderByDateTimeDesc(patientId,PageRequest.of(page,size));
        return list.map(converter::convertReport);
    }
}
/*
* List<Report> list=reportRepository.findAll();
        List<Report> reports=new ArrayList<>();
        for(Report report : list){
            if(report.getWorker().getName().contains(value) ||
                    report.getWorker().getLastName().contains(value)
            || report.getWorker().getIdentificationNumber().contains(value) ||
                    report.getPatient().getName().equals(value) ||
                    report.getPatient().getLastName().equals(value) ||
                    report.getPatient().getIdentificationNumber().contains(value)
            ){
                reports.add(report);
            }
        }
        return reports.stream().map(converter::convertReport).collect(Collectors.toList());
* */
