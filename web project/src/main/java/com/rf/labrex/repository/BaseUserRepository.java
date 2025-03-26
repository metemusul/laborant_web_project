package com.rf.labrex.repository;

import com.rf.labrex.entity.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BaseUserRepository extends JpaRepository<BaseUser,String> {
    Optional<BaseUser> findByIdentificationNumber(String number);
    boolean existsByIdentificationNumber(String number);
}
