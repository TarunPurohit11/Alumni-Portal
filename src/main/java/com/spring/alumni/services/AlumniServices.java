package com.spring.alumni.services;

import com.spring.alumni.dtos.ProfileDTO;
import com.spring.alumni.dtos.PublicProfileDTO;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AlumniServices {

    private final UserRepository userRepository;

    public Page<PublicProfileDTO> getPublicAlumni(int page, int size) {
        return userRepository.findPublicAlumni(PageRequest.of(page, size));
    }

    public ProfileDTO getAlumniProfile(Long userId) {
        User user =  userRepository.findById(userId).orElseThrow();
        return mapToProfileView(user);
    }

    private ProfileDTO mapToProfileView(User user) {

        return ProfileDTO.builder()
                .name(user.getName())
                .role(user.getRole().name())
                .profilePic(user.getProfilePic())
                // Alumni-only
                .title(user.getTitle())
                .company(user.getCompany())

                // Common
                .city(user.getCity())
                .about(user.getAbout())
                .skills(user.getSkills())

                // Student-only
                .course(user.getCourse())
                .year(user.getYear())

                .build();
    }


}
