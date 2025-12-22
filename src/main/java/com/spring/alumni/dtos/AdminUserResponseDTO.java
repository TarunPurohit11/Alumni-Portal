package com.spring.alumni.dtos;

import com.spring.alumni.entities.type.Role;
import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AdminUserResponseDTO {

    private Long id;

    // Auth
    private String username;      // email
    private Role role;
    private boolean enabled;

    // Profile
    private String name;
    private String profilePic;

    private String title;         // Alumni
    private String company;       // Alumni

    private String course;        // Student
    private Integer year;         // Student

    private String city;
    private String about;

    private List<String> skills;
}
