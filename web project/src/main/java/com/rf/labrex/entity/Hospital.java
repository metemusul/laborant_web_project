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
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Hospital {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "hospital_sequence")
    @SequenceGenerator(name = "hospital_sequence", sequenceName = "hospital_seq", allocationSize = 1, initialValue = 1000000)
    private Long id;
    private String name;
    @Lob
    private String image;
    @OneToMany(mappedBy = "hospital", cascade = CascadeType.REMOVE)
    @JsonIgnore
    List<LaboratoryWorker> workers;


}
