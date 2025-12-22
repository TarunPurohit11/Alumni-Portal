package com.spring.alumni.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PublicProfileDTO {
    private Long id;
    private String name;
    private String company;
    private String title;
    private Integer graduationYear;
    private String avatarUrl;
}
