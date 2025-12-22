package com.spring.alumni.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProfileDTO {
    private String name;
    private String role;       // STUDENT / ALUMNI
    private String title;      // Job title (alumni)
    private String company;    // Company (alumni)
    private String city;
    private String about;
    private List<String> skills;
    private String profilePic;
    private String course;     // Student only
    private Integer year;      // Graduation year
}
