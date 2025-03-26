package com.rf.labrex.repository;

import com.rf.labrex.entity.Patient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PatientRepository extends JpaRepository<Patient,String> {
    Patient findByIdentificationNumber(String number);
    boolean existsByIdentificationNumber(String number);
}
