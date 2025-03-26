package com.rf.labrex.service;

import com.rf.labrex.dto.SaveWorkerRequest;
import com.rf.labrex.dto.WorkerDto;
import com.rf.labrex.dto.converter.DtoConverter;
import com.rf.labrex.entity.Hospital;
import com.rf.labrex.entity.LaboratoryWorker;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.exception.NotFoundException;
import com.rf.labrex.repository.LaboratoryWorkerRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


// laborant işlemleri
@Service
@RequiredArgsConstructor
public class WorkerService {

    private final LaboratoryWorkerRepository workerRepository;
    private final HospitalService hospitalService;
    private final PasswordEncoder encoder;
    private final DtoConverter converter;
    public ApiResponse save(SaveWorkerRequest request, Long hospitalId, HttpServletRequest url) {
        LaboratoryWorker worker=request.toWorker(request);
        Hospital hospital=hospitalService.findById(hospitalId);
        worker.setHospital(hospital);
        worker.setPassword(encoder.encode(request.getPassword()));
        workerRepository.save(worker);
        ApiResponse apiResponse=new ApiResponse();
        apiResponse=ApiResponse.builder().status(200).path(url.getRequestURI()).dateTime(apiResponse.getDateTime()).message("Laborant Kaydoldu").build();
        return apiResponse;
    }

    public ApiResponse delete(String id, HttpServletRequest url) {
        LaboratoryWorker worker=findById(id);
        workerRepository.delete(worker);
        ApiResponse apiResponse=new ApiResponse();
        apiResponse=ApiResponse.builder().message("Laborant Silindi").dateTime(apiResponse.getDateTime()).status(200).path(url.getRequestURI()).build();
        return apiResponse;
    }

    protected LaboratoryWorker findById(String workerId) {
        return workerRepository.findById(workerId).orElseThrow(()->new NotFoundException("Laborant"));
    }

    public List<WorkerDto> list() {
        List<LaboratoryWorker> workers=workerRepository.findAll();
        return workers.stream().map(converter::convertWorker).collect(Collectors.toList());
    }
}
