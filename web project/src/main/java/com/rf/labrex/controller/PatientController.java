package com.rf.labrex.controller;

import com.rf.labrex.dto.PatientDto;
import com.rf.labrex.dto.SavePatientRequest;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.service.PatientService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1/patient")

public class PatientController {
    private final PatientService patientService;

    public PatientController(PatientService patientService) {
        this.patientService = patientService;
    }

    // hasta kayıt-Herkese Açık
    @PostMapping("/save")
    public ResponseEntity<ApiResponse> save(@Valid @RequestBody SavePatientRequest request, HttpServletRequest url){
        return ResponseEntity.ok(patientService.save(request,url));
    }
    // hasta silme -> bu işlemi sadece hasta ve admin yapabilir
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<ApiResponse> delete(@PathVariable String id,HttpServletRequest url){
        return ResponseEntity.ok(patientService.delete(id,url));
    }
    // tüm hastaların listelenmesi admin ve laborant
    @GetMapping("/list")
    public List<PatientDto> list(){
        return patientService.list();
    }
}
