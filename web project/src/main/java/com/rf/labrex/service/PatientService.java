package com.rf.labrex.service;

import com.rf.labrex.config.QueryConfig;
import com.rf.labrex.dto.PatientDto;
import com.rf.labrex.dto.SavePatientRequest;
import com.rf.labrex.dto.converter.DtoConverter;
import com.rf.labrex.entity.Patient;
import com.rf.labrex.entity.UserRole;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.exception.AuthorizationException;
import com.rf.labrex.exception.NotFoundException;
import com.rf.labrex.repository.PatientRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


// hasta işlemlerinin yapıldığı sınıf
@Service
@RequiredArgsConstructor
public class PatientService {

    private final PatientRepository patientRepository;
    private final PasswordEncoder encoder;
    private final DtoConverter converter;
    private final QueryConfig config;
    public ApiResponse save(SavePatientRequest request, HttpServletRequest url) {
        ApiResponse apiResponse=new ApiResponse();
        Patient patient=request.toPatient(request);
        patient.setPassword(encoder.encode(request.getPassword()));
        patientRepository.save(patient);
        apiResponse= ApiResponse.builder().status(200).path(url.getRequestURI()).dateTime(apiResponse.getDateTime()).message("Hasta Kayıt oldu").build();
        return apiResponse;
    }

    public ApiResponse delete(String id, HttpServletRequest url) {
        ApiResponse apiResponse=new ApiResponse();
        Patient patient=findById(id);
        if(!(config.getAuthentication().getRole()== UserRole.ROLE_ADMIN || config.isAuthorized(patient,config.getAuthentication()))) throw new AuthorizationException();
        patientRepository.delete(patient);
        apiResponse=ApiResponse.builder().status(200).message("Hasta Silindi").dateTime(apiResponse.getDateTime()).path(url.getRequestURI()).build();
        return apiResponse;
    }

    protected Patient findById(String patientId) {
        return patientRepository.findById(patientId).orElseThrow(()->new NotFoundException("Hasta"));
    }

    public List<PatientDto> list() {
        List<Patient> patients=patientRepository.findAll();
        return patients.stream().map(converter::convertPatient).collect(Collectors.toList());
    }
}
