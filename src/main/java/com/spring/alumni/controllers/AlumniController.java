package com.spring.alumni.controllers;

import com.spring.alumni.dtos.ProfileDTO;
import com.spring.alumni.dtos.PublicProfileDTO;
import com.spring.alumni.services.AlumniServices;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/alumni")
@RequiredArgsConstructor
public class AlumniController {

    private final AlumniServices alumniServices;

    @GetMapping("/public")
    public Page<PublicProfileDTO> getPublicAlumni(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "8") int size){
        return alumniServices.getPublicAlumni(page,size);
    }

    @GetMapping("profile/{userId}")
    public ProfileDTO getAlumniProfile(
            @PathVariable Long userId){
        return alumniServices.getAlumniProfile(userId);
    }
}
