package com.rf.labrex.repository;

import com.rf.labrex.entity.LaboratoryWorker;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LaboratoryWorkerRepository extends JpaRepository<LaboratoryWorker,String> {
Optional<LaboratoryWorker> findByIdentificationNumber(String number);
}
