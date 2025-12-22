package com.spring.alumni.controllers;

import com.spring.alumni.entities.Announcement;
import com.spring.alumni.services.AnnouncementServices;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/announcements")
@RequiredArgsConstructor
@CrossOrigin
public class AnnouncementController {

    private final AnnouncementServices announcementServices;

    @GetMapping("/active")
    public List<Announcement> getAnnouncements(){
        return announcementServices.getAllActiveAnnouncements();
    }
}
