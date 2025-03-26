package com.rf.labrex.controller;

import com.rf.labrex.dto.SaveWorkerRequest;
import com.rf.labrex.dto.WorkerDto;
import com.rf.labrex.dto.ApiResponse;
import com.rf.labrex.service.WorkerService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1/worker")

public class WorkerController {

    private final WorkerService workerService;

    public WorkerController(WorkerService workerService) {
        this.workerService = workerService;
    }

    /*BURADAKİ İŞLEMLERİ SADECE ADMİN YAPABİLİR*/
    // laborant oluştur
    @PostMapping("/save/{hospitalId}")
    ResponseEntity<ApiResponse> save(@Valid @RequestBody SaveWorkerRequest request,@PathVariable Long hospitalId ,HttpServletRequest url){
        return ResponseEntity.ok(workerService.save(request,hospitalId,url));
    }


    // laborant sil
    @DeleteMapping("/delete/{id}")
    ResponseEntity<ApiResponse> delete(@PathVariable String id, HttpServletRequest url){
        return ResponseEntity.ok(workerService.delete(id,url));
    }
    @GetMapping("/list")
    public List<WorkerDto> list(){
        return workerService.list();
    }

}
