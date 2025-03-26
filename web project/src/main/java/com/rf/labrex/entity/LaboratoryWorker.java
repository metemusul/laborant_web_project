package com.rf.labrex.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LaboratoryWorker extends BaseUser {
    private String name;
    private String lastName;
    @ManyToOne
    @JoinColumn(name = "hospitalId")
    private Hospital hospital;
    @OneToMany(mappedBy = "worker", cascade = CascadeType.REMOVE)
    @JsonIgnore
    List<Report> reports;

}
