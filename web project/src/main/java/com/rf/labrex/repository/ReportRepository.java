package com.rf.labrex.repository;

import com.rf.labrex.entity.Report;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ReportRepository extends JpaRepository<Report,String> {
    Page<Report> findByWorkerId(String workerId, Pageable pageable);
    Page<Report> findByPatientId(String patientId,Pageable pageable);
    Page<Report> findByWorkerIdOrderByDateTimeDesc(String workerId, Pageable pageable);
    Page<Report> findByPatientIdOrderByDateTimeDesc(String patientId, Pageable pageable);
    List<Report> findByWorkerNameContainingIgnoreCaseOrWorkerLastNameContainingIgnoreCaseOrWorkerIdentificationNumberContainingIgnoreCaseOrPatientNameContainingIgnoreCaseOrPatientLastNameContainingIgnoreCaseOrPatientIdentificationNumberContainingIgnoreCaseOrTitleContainingIgnoreCaseOrDetailsContainingIgnoreCase(String workerName, String workerLastName, String workerIdentificationNumber, String patientName, String patientLastName, String patientIdentificationNumber, String title, String details);
}
