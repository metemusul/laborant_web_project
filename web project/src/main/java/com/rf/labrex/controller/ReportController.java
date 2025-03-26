package com.rf.labrex.controller;

import com.rf.labrex.dto.ReportDto;
import com.rf.labrex.dto.SaveReportRequest;
import com.rf.labrex.dto.UpdateReportRequest;
import com.rf.labrex.service.ReportService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController()
@RequestMapping("api/v1/report")

public class ReportController {
    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }


    /*----BURADAKİ İŞLEMLERİ SADECE LABORANT YAPABİLİR----*/
    // rapor oluştur
    @PostMapping("/save/{workerId}/{patientId}")
    public ResponseEntity<?> save(@Valid @RequestBody SaveReportRequest request, @PathVariable String workerId, @PathVariable String patientId, HttpServletRequest url) {
        return ResponseEntity.ok(reportService.save(request,workerId,patientId,url));
    }

    // rapor güncelle
    @PutMapping("/update/{id}")
    public ResponseEntity<?> update(@Valid @RequestBody UpdateReportRequest request, @PathVariable String id, HttpServletRequest path) {
        return ResponseEntity.ok(reportService.update(request,id,path));
    }

    // rapor sil
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> delete(@PathVariable String id,HttpServletRequest path) {
        return ResponseEntity.ok(reportService.delete(id,path));
    }

    // laboranta ait raporlar
    @GetMapping("/list/worker/{workerId}")
    public Page<ReportDto> reportsForWorker(@PathVariable String workerId,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "50") int size ) {
        return reportService.reportsForWorker(workerId,page,size);
    }
    // Rapor tarihi ile sıralama laboranta ait raporlar
    @GetMapping("/sort/worker/{workerId}")
    public Page<ReportDto> sortByDate(@PathVariable String workerId,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "50") int size) {
        return reportService.sortByDate(workerId,page,size);
    }
    /*------------------------------------------------------*/

    /*BURADAKİ İŞLEMİ HASTA VE LABORANT YAPABİLİR*/
    // hastaya ait raporları görüntüleme
    @GetMapping("/list/patient/{patientId}")
    public Page reportsForPatients(@PathVariable String patientId,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "50") int size) {
        return reportService.reportsForPatient(patientId,page,size);
    }

    // herhangi bir raporu görüntüleme
    @GetMapping("/{id}")
    public ReportDto get(@PathVariable String id) {
        return reportService.getReport(id);
    }

    // Hasta Adı Soyadı kimlik numarasi ,Laboran Adi Soyadı ile Arama
    @GetMapping("/search/{value}")
    public List<ReportDto> search(@PathVariable String value) {
        return reportService.search(value);
    }

    // Rapor tarihi ile sıralama hastaya ait raporlar
    @GetMapping("/sort/patient/{PatientId}")
    public Page<ReportDto> sortingByDateForWorker(@PathVariable String patientId,@RequestParam(defaultValue = "0") int page,@RequestParam(defaultValue = "50") int size) {
        return reportService.sortingByDateForWorker(patientId,page,size);
    }
    /*---------------------------------------------*/

}
