package com.rf.labrex.controller;

import com.rf.labrex.dto.HospitalDto;
import com.rf.labrex.dto.SaveHospitalRequest;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.service.HospitalService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1/hospital")

public class HospitalController {
    private final HospitalService hospitalService;

    public HospitalController(HospitalService hospitalService) {
        this.hospitalService = hospitalService;
    }

    /*BURADAKİ İŞLEMLERİ SADECE ADMİN YAPABİLİR*/
    // hastane ekle
    @PostMapping("/save")
    ResponseEntity<HospitalDto> saveHospital(@Valid @RequestBody SaveHospitalRequest request){
        return ResponseEntity.ok().body(hospitalService.saveHospital(request));
    }
    // hastane sil
    @DeleteMapping("/delete/{id}")
    ResponseEntity<ApiResponse> deleteHospital(@PathVariable Long id, HttpServletRequest url){
        return ResponseEntity.ok().body(hospitalService.delete(id,url));
    }
    @GetMapping("/list")
    public List<HospitalDto> list(){
        return hospitalService.list();
    }


}
