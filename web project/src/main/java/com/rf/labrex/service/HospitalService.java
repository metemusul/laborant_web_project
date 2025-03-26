package com.rf.labrex.service;

import com.rf.labrex.dto.HospitalDto;
import com.rf.labrex.dto.SaveHospitalRequest;
import com.rf.labrex.dto.converter.DtoConverter;
import com.rf.labrex.entity.Hospital;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.exception.NotFoundException;
import com.rf.labrex.repository.HospitalRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


// hastane işlemlerinin yapıldığı sınıf
@Service
@RequiredArgsConstructor
public class HospitalService {
    private final HospitalRepository hospitalRepository;
    private final DtoConverter converter;

    public HospitalDto saveHospital(SaveHospitalRequest request) {
        Hospital hospital= Hospital.builder().name(request.getName()).image(request.getImage()).build();
        hospitalRepository.save(hospital);

        return converter.convertHospital(hospital);
    }

    public ApiResponse delete(Long id, HttpServletRequest url) {
        Hospital hospital=findById(id);
        hospitalRepository.delete(hospital);
        ApiResponse apiResponse=new ApiResponse();
        apiResponse=ApiResponse.builder().path(url.getRequestURI()).dateTime(apiResponse.getDateTime()).status(200).message("Hastane Silindi").build();
        return apiResponse;
    }

    protected Hospital findById(Long hospitalId) {
        return hospitalRepository.findById(hospitalId).orElseThrow(()-> new NotFoundException("Hastane"));
    }

    public List<HospitalDto> list() {
        List<Hospital> list=hospitalRepository.findAll();
        return list.stream().map(converter::convertHospital).collect(Collectors.toList());
    }
}
