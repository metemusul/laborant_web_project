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
public class Patient extends BaseUser{
    private String name;
    private String lastName;
    @OneToMany(mappedBy = "patient",cascade = CascadeType.REMOVE)
    @JsonIgnore
    private List<Report> reports;

}
