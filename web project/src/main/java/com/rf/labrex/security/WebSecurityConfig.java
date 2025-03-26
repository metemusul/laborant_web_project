package com.rf.labrex.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/*
-------------HERKESE AÇIK--------------------------------------
api/v1/auth/**
api/v1/patient/save
--------------SADECE ADMİN--------------------------------
api/v1/hospital/**
api/v1/worker/**
api/v1/report/search/{value}

----------------ADMİN VE LABORANT-------------------------------
api/v1/patient/list
---------------ADMİN VE HASTA--------------------------------------
api/v1/patient/delete/{id}
---------------------------------------------------------------------
--------------SADECE LABORANT-------------------------------------
api/v1/report/save/**
api/v1/report/update/{id}
api/v1/report/delete/{id}
api/v1/report/list/worker/{workerId}
api/v1/report/sort/worker/{workerId}
---------------HASTA VE LABORANT------------------------------------
api/v1/report/list/patient/{patientId}
api/v1/report/{id}

api/v1/report/sort/patient/**
-------------------------------------------------------------------------------
 */

// Bu sınıf security ayarlarının yapıldığı yer
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    public WebSecurityConfig(Filter filter) {
        this.filter = filter;
    }
    private final Filter filter;
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http)throws Exception{

       http.authorizeHttpRequests((a)->
                a.requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/hospital/**")).hasRole("ADMIN").
                        requestMatchers("/api/v1/worker/**","/api/v1/report/search/{value}").hasRole("ADMIN").
                        requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/patient/list")).hasAnyRole("ADMIN","WORKER").
                        requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/patient/delete/{id}")).hasAnyRole("ADMIN","PATIENT").
                        requestMatchers("/api/v1/report/save/**","/api/v1/report/update/**","/api/v1/report/delete/**","/api/v1/report/list/worker/{workerId}","/api/v1/report/sort/worker/{workerId}").hasRole("WORKER").

                        requestMatchers("/api/v1/report/list/patient/{patientId}","/api/v1/report/{id}","/api/v1/report/sort/patient/**").hasAnyRole("PATIENT","WORKER")


                       .anyRequest().permitAll()
                );

        http.csrf(x->x.disable());
        http.headers(x->x.disable());
        http.sessionManagement(x -> x.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
