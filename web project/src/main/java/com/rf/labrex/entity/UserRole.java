package com.rf.labrex.entity;

import org.springframework.security.core.GrantedAuthority;

public enum UserRole implements GrantedAuthority {
    ROLE_ADMIN("ADMIN"), ROLE_WORKER("WORKER"), ROLE_PATIENT("PATIENT");

    private String val;
    UserRole(String val){
        this.val=val;
    }
    @Override
    public String getAuthority() {
        return name();
    }
}
